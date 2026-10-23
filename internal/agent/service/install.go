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

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
)

// Runner runs one of the host's tools (by name: systemctl, launchctl,
// groupadd, ...) and returns its output; a non-zero exit is an error
// that carries the output.
type Runner func(ctx context.Context, tool string, args ...string) (string, error)

// System is a service manager: systemd or launchd. Its methods change
// the host only through run, but for Present, which only reads.
type System interface {
	// Present says whether the manager runs this host (root is the
	// host's root path), before anything is changed.
	Present(root string) error
	// DefinitionPath is where the definition goes.
	DefinitionPath() string
	// Render is the definition as this manager reads it.
	Render(d Definition) []byte
	// Start loads the definition just written and (re)starts the service;
	// an agent it ran before has exited first.
	Start(ctx context.Context, run Runner) error
	// Reload has the manager take a changed definition at the service's
	// next start, without restarting it.
	Reload(ctx context.Context, run Runner) error
	// Stop stops the service, keeping it enabled (it starts at boot), and
	// returns once its agent has exited (or the stop timed out, an
	// error).
	Stop(ctx context.Context, run Runner) error
	// Remove stops the service and has it start no more: Stop, and
	// disabled (systemd); launchd forgets a booted-out daemon until the
	// next boot, so uninstall removes its plist.
	Remove(ctx context.Context, run Runner) error
	// State is what the manager reports of the service now, a sentence
	// for an error (what it couldn't be asked is said so).
	State(ctx context.Context, run Runner) string
	// Forget is called once the definition is gone.
	Forget(ctx context.Context, run Runner) error
	// EnsureGroup makes the group if it is missing; AddToGroup adds a
	// user to it unless they are in it.
	EnsureGroup(ctx context.Context, run Runner, group string) error
	AddToGroup(ctx context.Context, run Runner, user, group string) error
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
	// LockHost takes the host's agent lock (agent.HostLock), failing with
	// agent.ErrAnotherAgent while an agent holds it.
	LockHost func() (func(), error)
	// ClearHost undoes what a crashed agent left on the host
	// (agent.Platform.ClearHost), under the host lock.
	ClearHost func() error
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

var (
	// ErrNotInstalled: no service definition.
	ErrNotInstalled = errors.New("the service is not installed")
	// ErrDefinitionChanged: a definition that isn't what install writes
	// (edited by hand).
	ErrDefinitionChanged = errors.New("the service's definition was changed by hand")
	// errAgentRuns: an agent holds the host lock where none may run.
	errAgentRuns = errors.New("a thinkpol agent runs outside the service (it holds the host lock): stop it, then run this again")
)

func (in Installer) path(p string) string { return filepath.Join(in.Root, p) }

func (in Installer) say(format string, args ...any) {
	if in.Out != nil {
		_, _ = fmt.Fprintf(in.Out, format+"\n", args...)
	}
}

// Install copies the binary, makes the group (adding opts.User), writes
// the definition and (re)starts the service. Run again, it replaces the
// binary and restarts the service, keeping connect-on-boot unless opts
// sets it. The binary directory's trust check, the group steps, then the
// binary, then the definition, all run before anything is stopped: a
// failure there leaves the installed service running as it was (a
// failure after the binary leaves the new binary for the old definition's
// next restart; the binary is renamed over, so the old agent runs on from
// its file, and the definition is read by the manager only at Start). With
// no service installed, an agent holding the host lock (one run by hand)
// refuses the install before anything changes. With one, its agent holds
// the lock, so the check comes after the stop. A refusal there, or a
// failed start, says what install knows first (leftAfter): the installed
// service stopped, the definition on disk, what the manager reports now.
func (in Installer) Install(ctx context.Context, opts Options) error {
	if err := in.System.Present(in.Root); err != nil {
		return err
	}
	if err := in.Ready(); err != nil {
		return fmt.Errorf("this node can't run yet: %w", err)
	}
	_, err := os.Lstat(in.path(in.System.DefinitionPath()))
	defined := err == nil
	if !defined {
		if err := in.noAgent(); err != nil {
			return err
		}
	}
	connect := false
	d, err := in.installed()
	switch {
	case err == nil:
		connect = d.ConnectOnBoot
	case errors.Is(err, ErrNotInstalled):
	default:
		in.say("warning: %v; installing anew, connect-on-boot off unless -connect-on-boot says otherwise", err)
	}
	if opts.ConnectOnBoot != nil {
		connect = *opts.ConnectOnBoot
	}
	if err := in.binaryDirTrusted(); err != nil {
		return err
	}
	if err := in.System.EnsureGroup(ctx, in.Run, Group); err != nil {
		return fmt.Errorf("group %s: %w", Group, err)
	}
	if opts.User != "" {
		if err := in.System.AddToGroup(ctx, in.Run, opts.User, Group); err != nil {
			return fmt.Errorf("adding %s to group %s: %w", opts.User, Group, err)
		}
		in.say("%s is in group %s: the local API is theirs from their next login", opts.User, Group)
	}
	if err := in.installBinary(); err != nil {
		return err
	}
	if err := in.writeDefinition(Definition{Binary: BinaryPath, ConnectOnBoot: connect}); err != nil {
		return err
	}
	if defined {
		if err := in.System.Stop(ctx, in.Run); err != nil {
			return fmt.Errorf("stopping the installed service: %w", err)
		}
		if err := in.noAgent(); err != nil {
			return fmt.Errorf("%s: %w", in.leftAfter(ctx, defined), err)
		}
	}
	if err := in.System.Start(ctx, in.Run); err != nil {
		return fmt.Errorf("%s; starting it failed: %w", in.leftAfter(ctx, defined), err)
	}
	in.say("installed and started %s (connect-on-boot %s)", in.System.DefinitionPath(), OnOff(connect))
	return nil
}

// leftAfter says what an install that stops short of a start leaves, as
// far as it knows: the installed service stopped (stopped: there was
// one, stopped above), the definition on disk, and what the manager reports
// of the service now (System.State), which install doesn't claim
// otherwise.
func (in Installer) leftAfter(ctx context.Context, stopped bool) string {
	what := "the definition is on disk"
	if stopped {
		what = "the installed service was stopped and the new definition is on disk"
	}
	return fmt.Sprintf("%s (%s); %s", what, in.System.DefinitionPath(), in.System.State(ctx, in.Run))
}

// noAgent fails while an agent holds the host lock.
func (in Installer) noAgent() error {
	unlock, err := in.LockHost()
	if errors.Is(err, agent.ErrAnotherAgent) {
		return errAgentRuns
	}
	if err != nil {
		return err
	}
	unlock()
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
// stops), then, holding the host lock (refused while an agent still holds
// it), undoes what a crashed agent left on the host (ClearHost), removes
// the definition, the binary, and what the stopped agent left in its
// runtime directories. The group stays (it may be older than the
// service); so does the node's state directory, its keys and map.
func (in Installer) Uninstall(ctx context.Context) error {
	_, err := os.Lstat(in.path(in.System.DefinitionPath()))
	defined := err == nil
	if err := in.System.Remove(ctx, in.Run); err != nil && defined {
		return fmt.Errorf("stopping the service: %w", err)
	}
	unlock, err := in.LockHost()
	if errors.Is(err, agent.ErrAnotherAgent) {
		return errAgentRuns
	}
	if err != nil {
		return err
	}
	defer unlock()
	if err := in.ClearHost(); err != nil {
		return fmt.Errorf("undoing what a crashed agent left: %w", err)
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
	for _, dir := range in.RuntimeDirs {
		left, err := clearRuntimeDir(in.path(dir))
		if err != nil {
			return err
		}
		if len(left) > 0 {
			in.say("left in %s, not the agent's locks or boot records: %s", dir, strings.Join(left, ", "))
		}
	}
	in.say("the group %s stays; remove it yourself if nothing else uses it", Group)
	return nil
}

// installed reads the installed definition: exactly what install writes,
// connect-on-boot on or off; none is ErrNotInstalled, anything else
// ErrDefinitionChanged.
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
	return Definition{}, fmt.Errorf("%w: %s isn't what thinkpol service install writes; install again", ErrDefinitionChanged, in.System.DefinitionPath())
}

// writeDefinition replaces the definition atomically, 0644.
func (in Installer) writeDefinition(d Definition) error {
	return replaceFile(in.path(in.System.DefinitionPath()), in.System.Render(d), 0o644)
}

// installBinary copies the running binary to BinaryPath, unless that is
// already a regular file of root's (this process's user), 0755, and the
// same file: a symlink or anyone else's file
// there is replaced, so root's service never runs what a user could
// change. Its directory must be one no one else can change (trusteddir).
// binaryDirTrusted makes the binary's directory if it is missing and
// refuses one others can change: whoever could replace the binary would
// run as root. Install checks it before changing anything else.
func (in Installer) binaryDirTrusted() error {
	dir := filepath.Dir(in.path(BinaryPath))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := checkTrusted(dir); err != nil {
		return fmt.Errorf("the service's binary would be in a directory others can change: %w", err)
	}
	return nil
}

func (in Installer) installBinary() error {
	dst := in.path(BinaryPath)
	if err := in.binaryDirTrusted(); err != nil {
		return err
	}
	src, err := os.Stat(in.Executable)
	if err != nil {
		return err
	}
	if cur, err := os.Lstat(dst); err == nil && ownedSafely(cur) && cur.Mode().Perm() == 0o755 && os.SameFile(src, cur) {
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
	return strings.HasSuffix(name, ".lock") || name == agent.ConnectRecordFile
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
