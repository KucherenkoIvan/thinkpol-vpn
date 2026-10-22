package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Runner runs one of the host's tools (by name: systemctl, launchctl,
// groupadd, ...) and returns its output; a non-zero exit is an error
// that carries the output.
type Runner func(ctx context.Context, tool string, args ...string) (string, error)

// System is a service manager: systemd or launchd. Its methods change
// the host only through run.
type System interface {
	// DefinitionPath is where the definition goes.
	DefinitionPath() string
	// Render is the definition as this manager reads it.
	Render(d Definition) []byte
	// Start loads the definition just written and (re)starts the service.
	Start(ctx context.Context, run Runner) error
	// Reload has the manager take a changed definition at the service's
	// next start, without restarting it.
	Reload(ctx context.Context, run Runner) error
	// Stop stops and unloads the service; done once it isn't loaded.
	Stop(ctx context.Context, run Runner) error
	// Forget is called once the definition is gone.
	Forget(ctx context.Context, run Runner) error
	// EnsureGroup makes the group if it is missing; AddToGroup adds a
	// user to it; DeleteGroup removes it if it is there.
	EnsureGroup(ctx context.Context, run Runner, group string) error
	AddToGroup(ctx context.Context, run Runner, user, group string) error
	DeleteGroup(ctx context.Context, run Runner, group string) error
}

// Installer installs, changes and removes the service on a host.
type Installer struct {
	// Root is where the host's paths are: "/" (a test's: a temporary
	// directory).
	Root string
	// System is the host's service manager.
	System System
	// Run runs the manager's tools.
	Run Runner
	// Executable is the running thinkpol, which install copies to
	// BinaryPath.
	Executable string
	// Ready says whether the node can run (its state directory), checked
	// before anything is installed.
	Ready func() error
	// RuntimeDirs are where the agent keeps its locks and boot records
	// (the agent's lock directory, the local API's): uninstall removes
	// what a stopped agent leaves there.
	RuntimeDirs []string
	// Out hears what was done and what was left.
	Out io.Writer
}

// Options are install's choices.
type Options struct {
	// ConnectOnBoot sets connect-on-boot; nil keeps what an installed
	// service has, or off.
	ConnectOnBoot *bool
	// User is added to Group, so it may use the local API; "" adds no
	// one.
	User string
}

// ErrNotInstalled: no service definition, or not one install wrote.
var ErrNotInstalled = errors.New("the service is not installed")

func (in Installer) path(p string) string { return filepath.Join(in.Root, p) }

func (in Installer) say(format string, args ...any) {
	if in.Out != nil {
		_, _ = fmt.Fprintf(in.Out, format+"\n", args...)
	}
}

// Install copies the binary, makes the group (adding opts.User), writes
// the definition and (re)starts the service. Run again, it replaces the
// binary and restarts the service, keeping connect-on-boot unless opts
// sets it.
func (in Installer) Install(ctx context.Context, opts Options) error {
	if err := in.Ready(); err != nil {
		return fmt.Errorf("this node can't run yet: %w", err)
	}
	connect := false
	if opts.ConnectOnBoot != nil {
		connect = *opts.ConnectOnBoot
	} else if d, err := in.installed(); err == nil {
		connect = d.ConnectOnBoot
	}
	if err := in.installBinary(); err != nil {
		return err
	}
	if err := in.System.EnsureGroup(ctx, in.Run, Group); err != nil {
		return fmt.Errorf("group %s: %w", Group, err)
	}
	if opts.User != "" {
		if err := in.System.AddToGroup(ctx, in.Run, opts.User, Group); err != nil {
			return fmt.Errorf("adding %s to group %s: %w", opts.User, Group, err)
		}
		in.say("added %s to group %s: the local API is theirs from their next login", opts.User, Group)
	}
	if err := in.writeDefinition(Definition{Binary: BinaryPath, ConnectOnBoot: connect}); err != nil {
		return err
	}
	if err := in.System.Start(ctx, in.Run); err != nil {
		return fmt.Errorf("starting the service: %w", err)
	}
	in.say("installed and started %s (connect-on-boot %s)", in.System.DefinitionPath(), OnOff(connect))
	return nil
}

// ConnectOnBoot is the installed service's connect-on-boot.
func (in Installer) ConnectOnBoot() (bool, error) {
	d, err := in.installed()
	return d.ConnectOnBoot, err
}

// SetConnectOnBoot rewrites the installed definition with connect-on-boot
// on or off. The running agent isn't restarted: the setting is read at
// the boot's first start only.
func (in Installer) SetConnectOnBoot(ctx context.Context, on bool) error {
	d, err := in.installed()
	if err != nil {
		return err
	}
	d.ConnectOnBoot = on
	if err := in.writeDefinition(d); err != nil {
		return err
	}
	if err := in.System.Reload(ctx, in.Run); err != nil {
		return err
	}
	in.say("connect-on-boot %s: from the next boot", OnOff(on))
	return nil
}

// Uninstall stops the service (the agent takes its data plane down as it
// stops), removes the definition, the binary and the group, and what the
// stopped agent left in its runtime directories. The node's state
// directory (its keys and map) stays.
func (in Installer) Uninstall(ctx context.Context) error {
	_, err := os.Lstat(in.path(in.System.DefinitionPath()))
	defined := err == nil
	if err := in.System.Stop(ctx, in.Run); err != nil && defined {
		return fmt.Errorf("stopping the service: %w", err)
	}
	if defined {
		if err := os.Remove(in.path(in.System.DefinitionPath())); err != nil {
			return err
		}
		if err := in.System.Forget(ctx, in.Run); err != nil {
			return err
		}
		in.say("stopped and removed %s", in.System.DefinitionPath())
	}
	if err := os.Remove(in.path(BinaryPath)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if err := in.System.DeleteGroup(ctx, in.Run, Group); err != nil {
		return fmt.Errorf("group %s: %w", Group, err)
	}
	for _, dir := range in.RuntimeDirs {
		left, err := clearRuntimeDir(in.path(dir))
		if err != nil {
			return err
		}
		if len(left) > 0 {
			in.say("left in %s, not the agent's locks or boot records: %s", dir, strings.Join(left, ", "))
		}
	}
	return nil
}

// installed reads the installed definition: exactly what install writes,
// connect-on-boot on or off; anything else is ErrNotInstalled.
func (in Installer) installed() (Definition, error) {
	data, err := os.ReadFile(in.path(in.System.DefinitionPath()))
	if errors.Is(err, fs.ErrNotExist) {
		return Definition{}, ErrNotInstalled
	}
	if err != nil {
		return Definition{}, err
	}
	for _, on := range []bool{false, true} {
		d := Definition{Binary: BinaryPath, ConnectOnBoot: on}
		if bytes.Equal(data, in.System.Render(d)) {
			return d, nil
		}
	}
	return Definition{}, fmt.Errorf("%w: %s isn't what thinkpol service install writes; install again", ErrNotInstalled, in.System.DefinitionPath())
}

// writeDefinition replaces the definition atomically, 0644.
func (in Installer) writeDefinition(d Definition) error {
	return replaceFile(in.path(in.System.DefinitionPath()), in.System.Render(d), 0o644)
}

// installBinary copies the running binary to BinaryPath, unless it is
// that file. Root runs it, so its directory must be one no one else can
// change (trusteddir): whoever could replace the binary would run as root.
func (in Installer) installBinary() error {
	dst := in.path(BinaryPath)
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := checkTrusted(filepath.Dir(dst)); err != nil {
		return fmt.Errorf("the service's binary would be in a directory others can change: %w", err)
	}
	src, err := os.Stat(in.Executable)
	if err != nil {
		return err
	}
	if cur, err := os.Stat(dst); err == nil && os.SameFile(src, cur) {
		return nil
	}
	data, err := os.ReadFile(in.Executable)
	if err != nil {
		return err
	}
	return replaceFile(dst, data, 0o755)
}

// replaceFile writes data to a new file next to path and renames it over
// path: readers see the old file or the new one, whole.
func replaceFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	err = errors.Join(func() error { _, err := f.Write(data); return err }(), f.Chmod(perm), f.Sync())
	if err = errors.Join(err, f.Close()); err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// runtimeFile is what a stopped agent leaves in its runtime directories:
// locks (the agent's, netcfg's, the local API's) and the boot's connect
// record (agent.ConnectRecordFile), plus a record's temporary file. A
// socket there is a stopped service's too.
func runtimeFile(name string) bool {
	name = strings.TrimSuffix(name, ".tmp")
	return strings.HasSuffix(name, ".lock") || name == "connect"
}

// clearRuntimeDir removes the runtime files and sockets in dir and in its
// subdirectories, then every directory left empty, dir included. Anything
// else stays (a crashed run's records, which name what it left on the
// host) and is returned. A missing dir is fine; a symlink is left alone.
func clearRuntimeDir(dir string) ([]string, error) {
	fi, err := os.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return []string{dir}, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var left []string
	for _, e := range entries {
		p := filepath.Join(dir, e.Name())
		switch {
		case e.IsDir():
			l, err := clearRuntimeDir(p)
			if err != nil {
				return nil, err
			}
			left = append(left, l...)
		case e.Type().IsRegular() && runtimeFile(e.Name()), e.Type() == fs.ModeSocket:
			if err := os.Remove(p); err != nil {
				return nil, err
			}
		default:
			left = append(left, p)
		}
	}
	if len(left) == 0 {
		if err := os.Remove(dir); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	slices.Sort(left)
	return left, nil
}
