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
	"time"

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
	// before anything is installed, and which mode the service is
	// installed for (agent.ServiceMode; known false: the node's kind isn't
	// known, and it is installed as a server): a device's definition sends
	// the agent's stderr to CrashTrace, a server's sends it nowhere on
	// disk.
	Ready func() (mode agent.Mode, known bool, err error)
	// CrashTrace is the device's crash trace file (agent.CrashTracePath),
	// as the definition names it. A device's install makes it anew, 0600,
	// before the service starts (agent.CreateCrashTrace); a server's
	// install, and uninstall, remove it, once the service is stopped.
	CrashTrace string
	// LockHost takes the host's agent lock (agent.HostLock), failing with
	// agent.ErrAnotherAgent while an agent holds it.
	LockHost func() (func(), error)
	// ClearHost undoes what a crashed agent left on the host
	// (agent.Platform.ClearHost), under the host lock, and says what it
	// undid.
	ClearHost func() ([]string, error)
	// RuntimeDirs are where the agent keeps its locks and boot records
	// (the agent's lock directory, the local API's): uninstall removes
	// what a stopped agent leaves there.
	RuntimeDirs []string
	// Out hears what was done and what was left.
	Out io.Writer
}

// Options are install's choices.
type Options struct {
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
	// errOldDefinition: a definition from before connect-on-boot moved to
	// the device's settings.
	errOldDefinition = errors.New("the service's definition carries connect-on-boot")
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
// binary and restarts the service. The binary directory's trust check, the group steps, then the
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
	mode, known, err := in.Ready()
	if err != nil {
		return fmt.Errorf("this node can't run yet: %w", err)
	}
	if !known {
		in.say("warning: this node's kind isn't known (it isn't in its map): installing a server's definition, which keeps no crash trace; install again once a map includes it")
	}
	def := in.definition(mode)
	_, err = os.Lstat(in.path(in.System.DefinitionPath()))
	defined := err == nil
	if !defined {
		if err := in.noAgent(); err != nil {
			return err
		}
	}
	err = in.installed()
	if errors.Is(err, errOldDefinition) {
		in.say("connect-on-boot is no longer in the service's definition: it is the device's setting now, off until a member turns it on (thinkpol connect-on-boot on)")
	}
	if errors.Is(err, ErrDefinitionChanged) || err != nil && !errors.Is(err, errOldDefinition) && !errors.Is(err, ErrNotInstalled) {
		in.say("warning: %v; installing anew", err)
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
	if err := in.writeDefinition(def); err != nil {
		return err
	}
	if defined {
		if err := in.System.Stop(ctx, in.Run); err != nil {
			return fmt.Errorf("the new binary and definition are on disk; stopping the installed service failed: %w", err)
		}
		if err := in.noAgent(); err != nil {
			return fmt.Errorf("%s: %w", in.leftAfter(ctx, true), err)
		}
	}
	// After the stop: an agent crashing before it would write the file anew.
	if def.CrashTrace == "" {
		in.removeCrashTrace()
	} else if err := agent.CreateCrashTrace(in.path(def.CrashTrace)); err != nil {
		return fmt.Errorf("%s; making the crash trace %s failed: %w", in.leftAfter(ctx, defined), def.CrashTrace, err)
	}
	if err := in.System.Start(ctx, in.Run); err != nil {
		return fmt.Errorf("%s; starting it failed: %w", in.leftAfter(ctx, defined), err)
	}
	in.say("installed and started %s", in.System.DefinitionPath())
	return nil
}

// leftAfter says what an install that stops short of a start leaves, as
// far as it knows: the installed service stopped (stoppedOne: install
// stopped one above), the definition on disk, and what the manager
// reports of the service now (System.State), asked within stateWait of
// its own, so a wedged manager doesn't hold the real error back.
func (in Installer) leftAfter(ctx context.Context, stoppedOne bool) string {
	what := "the definition is on disk"
	if stoppedOne {
		what = "the installed service was stopped and the new definition is on disk"
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), stateWait)
	defer cancel()
	return fmt.Sprintf("%s (%s); %s", what, in.System.DefinitionPath(), in.System.State(sctx, in.Run))
}

// stateWait bounds the reads of leftAfter's state.
const stateWait = 5 * time.Second

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

// Uninstall stops the service (the agent takes its data plane down as it
// stops), then, holding the host lock (refused while an agent still holds
// it), undoes what a crashed agent left on the host (ClearHost: a
// device's and a server's), removes the definition, the binary, the
// device's crash trace, and what the stopped agent left in its runtime
// directories. The group stays (it
// may be older than the service); so does the node's state directory,
// its keys and map.
//
// A ClearHost that fails stops it there, the service stopped and disabled
// but its definition and binary on disk, so the binary is there to try
// again (launchd loads a definition left on disk at the next boot); force
// goes on, the failure reported as what is left on the host (a record the
// cleanup can't read, such as a DNS backup readBackup rejects on macOS,
// fails every try). With neither on disk there is nothing to keep, so it
// goes on as force does.
func (in Installer) Uninstall(ctx context.Context, force bool) error {
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
	undone, err := in.ClearHost()
	for _, u := range undone {
		in.say("undid what a crashed agent left: %s", u)
	}
	if err != nil {
		if left := in.onDisk(defined); left != "" && !force {
			return fmt.Errorf("undoing what a crashed agent left failed: %w\nthe service is stopped, but %s; run this again once that is fixed, or with -force to remove them anyway and leave this on the host", err, left)
		}
		in.say("warning: left on the host, undo it yourself: %v", err)
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
	in.removeCrashTrace()
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

// onDisk says what an uninstall stopped after the service's removal
// leaves of it on disk, "" for nothing.
func (in Installer) onDisk(defined bool) string {
	var left []string
	if defined {
		left = append(left, fmt.Sprintf("its definition (%s)", in.System.DefinitionPath()))
	}
	if _, err := os.Lstat(in.path(BinaryPath)); err == nil {
		left = append(left, fmt.Sprintf("its binary (%s)", BinaryPath))
	}
	if len(left) == 0 {
		return ""
	}
	verb := "is"
	if len(left) > 1 {
		verb = "are"
	}
	return fmt.Sprintf("%s %s still on disk", strings.Join(left, " and "), verb)
}

// installed checks the installed definition is exactly what install
// writes: none is ErrNotInstalled, one written before connect-on-boot
// moved to the device's settings errOldDefinition (and also
// ErrDefinitionChanged when it isn't what the older install wrote either),
// anything else ErrDefinitionChanged.
func (in Installer) installed() error {
	data, err := os.ReadFile(in.path(in.System.DefinitionPath()))
	if errors.Is(err, fs.ErrNotExist) {
		return ErrNotInstalled
	}
	if err != nil {
		return err
	}
	// Either mode's: the node's mode may have changed since.
	for _, mode := range []agent.Mode{agent.ModeDevice, agent.ModeServer} {
		if bytes.Equal(data, in.System.Render(in.definition(mode))) {
			return nil
		}
	}
	changed := fmt.Errorf("%w: %s isn't what thinkpol service install writes; install again", ErrDefinitionChanged, in.System.DefinitionPath())
	if !bytes.Contains(data, []byte(oldConnectOnBootVariable)) {
		return changed
	}
	for _, old := range oldDefinitions(in.System) {
		if bytes.Equal(data, old) {
			return errOldDefinition
		}
	}
	return &oldChangedError{changed}
}

// oldChangedError is an old definition (errOldDefinition) that was also
// changed by hand (ErrDefinitionChanged, its message).
type oldChangedError struct{ changed error }

func (e *oldChangedError) Error() string   { return e.changed.Error() }
func (e *oldChangedError) Unwrap() []error { return []error{errOldDefinition, e.changed} }

// oldConnectOnBootVariable is how definitions carried connect-on-boot
// before it moved to the device's settings (agent.DeviceFile).
const oldConnectOnBootVariable = "THINKPOL_CONNECT_ON_BOOT"

// definition is what install writes for a node that runs in mode.
func (in Installer) definition(mode agent.Mode) Definition {
	d := Definition{Binary: BinaryPath}
	if mode != agent.ModeServer {
		d.CrashTrace = in.CrashTrace
	}
	return d
}

// removeCrashTrace removes the crash trace file, if there is one: a
// server keeps none, and the service's is gone with it. One that can't be
// removed is said.
func (in Installer) removeCrashTrace() {
	if in.CrashTrace == "" {
		return
	}
	err := os.Remove(in.path(in.CrashTrace))
	switch {
	case err == nil:
		in.say("removed the crash trace %s", in.CrashTrace)
	case !errors.Is(err, fs.ErrNotExist):
		in.say("warning: the crash trace %s stays: %v", in.CrashTrace, err)
	}
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
