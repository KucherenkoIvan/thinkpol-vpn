//go:build linux || darwin

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// fakeHost is a host's service manager and groups, in memory: what the
// tools' runs leave, for tests to check the state rather than the calls.
type fakeHost struct {
	t    *testing.T
	root string

	mu sync.Mutex
	// groups and their members.
	groups   map[string][]string
	failNext map[string]int // tool+" "+first arg: fail that many runs
	// systemd: the unit as daemon-reload last read it (nil: unknown), the
	// unit the running agent was started from (nil: not running), enabled.
	unitLoaded, unitRunning []byte
	enabled                 bool
	// launchd: the daemon loaded, from which plist; goneAfter: prints that
	// still show it after a bootout; disabled: an override someone set;
	// overridden: an override was written (enable or disable).
	loaded               bool
	loadedFrom           []byte
	booting, goneAfter   int
	disabled, overridden bool
	// bootoutFails: bootout reports an error ("Operation now in
	// progress") though the teardown goes on; printFails: print fails
	// for another reason than no such service.
	bootoutFails, printFails bool
	// traceAtStart is the crash trace file as the manager found it at the
	// last start (nil: none); crashOnStop: the stopped agent writes a
	// trace as it dies.
	traceAtStart os.FileInfo
	crashOnStop  bool
	// bootstrapEIO: bootstraps refused with launchd's EIO before one is
	// taken; bootstrapEIOLoaded: ones that say EIO but load the job.
	bootstrapEIO, bootstrapEIOLoaded int
	// oldSystemd: a systemd that doesn't load a unit file for a stop.
	oldSystemd bool
	// printFailsAfterEIO: print starts failing once a bootstrap was
	// refused with EIO.
	printFailsAfterEIO bool
	// cleared counts ClearHost's runs, and heldWhileCleared whether the
	// host lock was held at each.
	cleared, heldWhileCleared int
}

// testCrashTrace is the fake host's crash trace file, and
// deviceDefinition what install writes for a device on it.
const testCrashTrace = "/var/lib/thinkpol/crash-trace"

var deviceDefinition = Definition{Binary: BinaryPath, CrashTrace: testCrashTrace}

func newFakeHost(t *testing.T) *fakeHost {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &fakeHost{t: t, root: root, groups: map[string][]string{}, failNext: map[string]int{}}
}

func (h *fakeHost) run(_ context.Context, tool string, args ...string) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := tool + " " + args[0]
	if h.failNext[key] > 0 {
		h.failNext[key]--
		return "", fmt.Errorf("%s: failing on purpose", key)
	}
	trace := filepath.Join(h.root, testCrashTrace)
	switch key {
	case "systemctl restart", "launchctl bootstrap":
		h.traceAtStart, _ = os.Lstat(trace)
	case "systemctl stop", "launchctl bootout":
		if h.crashOnStop {
			if err := os.WriteFile(trace, []byte("panic: on the way out\n"), 0o644); err != nil {
				h.t.Error(err)
			}
		}
	}
	switch tool {
	case "systemctl":
		return h.systemctl(args)
	case "launchctl":
		return h.launchctl(args)
	case "groupadd", "usermod", "dseditgroup":
		return h.group(tool, args)
	}
	h.t.Errorf("unexpected tool %s %v", tool, args)
	return "", errors.New("no such tool")
}

func (h *fakeHost) unitFile() []byte {
	data, err := os.ReadFile(filepath.Join(h.root, UnitPath))
	if err != nil {
		return nil
	}
	return data
}

func (h *fakeHost) systemctl(args []string) (string, error) {
	// systemd 252 loads a unit file it hasn't read yet for a stop (seen in
	// the lab); one that doesn't (oldSystemd) answers "not loaded".
	if (slices.Equal(args, []string{"stop", UnitName}) || slices.Equal(args, []string{"disable", "--now", UnitName})) &&
		h.unitLoaded == nil && h.unitFile() != nil && !h.oldSystemd {
		h.unitLoaded = h.unitFile()
	}
	notLoaded := func() (string, error) {
		out := "Failed to stop thinkpol.service: Unit thinkpol.service not loaded."
		return out, fmt.Errorf("systemctl %v: %w: %s", args, exitError(h.t, 5), out)
	}
	switch {
	case slices.Equal(args, []string{"daemon-reload"}):
		h.unitLoaded = h.unitFile()
	case slices.Equal(args, []string{"enable", UnitName}) && h.unitLoaded != nil:
		h.enabled = true
	case slices.Equal(args, []string{"restart", UnitName}) && h.unitLoaded != nil:
		h.unitRunning = h.unitLoaded
	case slices.Equal(args, []string{"stop", UnitName}) && h.unitLoaded != nil:
		h.unitRunning = nil
	case slices.Equal(args, []string{"disable", "--now", UnitName}) && h.unitLoaded != nil:
		h.enabled, h.unitRunning = false, nil
	case slices.Equal(args, []string{"disable", "--now", UnitName}) && h.unitFile() != nil:
		h.enabled = false // disable acts on the file; the stop finds no unit
		return notLoaded()
	case slices.Equal(args, []string{"stop", UnitName}):
		return notLoaded()
	case slices.Equal(args, []string{"is-enabled", UnitName}) && h.unitFile() != nil:
		if h.enabled {
			return "enabled\n", nil
		}
		return "disabled\n", fmt.Errorf("systemctl is-enabled: %w", exitError(h.t, 1))
	case slices.Equal(args, []string{"is-active", UnitName}):
		if h.unitRunning != nil {
			return "active\n", nil
		}
		return "inactive\n", fmt.Errorf("systemctl is-active: %w", exitError(h.t, 3))
	case slices.Equal(args, []string{"reset-failed", UnitName}):
	default:
		return "", fmt.Errorf("systemctl %v: refused", args)
	}
	return "", nil
}

// exitError is a real *exec.ExitError with code, as runTool wraps one.
func exitError(t *testing.T, code int) error {
	err := exec.Command("sh", "-c", fmt.Sprintf("exit %d", code)).Run()
	var x *exec.ExitError
	if !errors.As(err, &x) || x.ExitCode() != code {
		t.Fatalf("no exit error %d: %v", code, err)
	}
	return err
}

func (h *fakeHost) launchctl(args []string) (string, error) {
	switch {
	case slices.Equal(args, []string{"print", target}) && h.printFails:
		return "launchctl: Operation not permitted", fmt.Errorf("launchctl print: %w: Operation not permitted", exitError(h.t, 1))
	case slices.Equal(args, []string{"print", target}):
		if h.booting > 0 {
			h.booting--
			return "", nil
		}
		if !h.loaded {
			out := "Could not find service \"" + Label + "\" in domain for system"
			return out, fmt.Errorf("launchctl print: %w: %s", exitError(h.t, 113), out)
		}
	case slices.Equal(args, []string{"bootout", target}) && h.loaded:
		h.loaded, h.loadedFrom, h.booting = false, nil, h.goneAfter
		if h.bootoutFails {
			return "", errors.New("Boot-out failed: 36: Operation now in progress")
		}
	case slices.Equal(args, []string{"print-disabled", "system"}):
		v := "enabled"
		if h.disabled {
			v = "disabled"
		}
		if !h.overridden {
			return "disabled services = {\n}\n", nil
		}
		return fmt.Sprintf("disabled services = {\n\t\"com.example.other\" => disabled\n\t%q => %s\n}\n", Label, v), nil
	case slices.Equal(args, []string{"enable", target}):
		h.disabled, h.overridden = false, true
	case slices.Equal(args, []string{"bootstrap", "system", PlistPath}) && h.bootstrapEIOLoaded > 0 && !h.loaded:
		h.bootstrapEIOLoaded--
		data, err := os.ReadFile(filepath.Join(h.root, PlistPath))
		if err != nil {
			return "", err
		}
		h.loaded, h.loadedFrom = true, data
		return "Bootstrap failed: 5: Input/output error", fmt.Errorf("launchctl bootstrap: %w: Bootstrap failed: 5: Input/output error", exitError(h.t, 5))
	case slices.Equal(args, []string{"bootstrap", "system", PlistPath}) && h.bootstrapEIO > 0:
		h.bootstrapEIO--
		h.printFails = h.printFails || h.printFailsAfterEIO
		return "Bootstrap failed: 5: Input/output error", fmt.Errorf("launchctl bootstrap: %w: Bootstrap failed: 5: Input/output error", exitError(h.t, 5))
	case slices.Equal(args, []string{"bootstrap", "system", PlistPath}) && !h.loaded && h.booting == 0 && !h.disabled:
		data, err := os.ReadFile(filepath.Join(h.root, PlistPath))
		if err != nil {
			return "", err
		}
		h.loaded, h.loadedFrom = true, data
	default:
		return "", fmt.Errorf("launchctl %v: refused", args)
	}
	return "", nil
}

func (h *fakeHost) group(tool string, args []string) (string, error) {
	name := args[len(args)-1]
	members, exists := h.groups[name]
	switch {
	case tool == "groupadd" && slices.Equal(args[:2], []string{"-f", "-r"}):
		if !exists {
			h.groups[name] = nil
		}
	case tool == "dseditgroup" && args[1] == "create" && !exists:
		h.groups[name] = nil
	case tool == "dseditgroup" && args[1] == "read" && exists:
	case tool == "dseditgroup" && args[1] == "checkmember" && slices.Contains(members, args[3]):
	case tool == "usermod" && slices.Equal(args[:2], []string{"-a", "-G"}) && h.hasGroup(args[2]):
		if !slices.Contains(h.groups[args[2]], args[3]) {
			h.groups[args[2]] = append(h.groups[args[2]], args[3])
		}
	case tool == "dseditgroup" && args[1] == "edit" && args[2] == "-a" && exists && !slices.Contains(members, args[3]):
		h.groups[name] = append(members, args[3])
	default:
		return "", fmt.Errorf("%s %v: refused", tool, args)
	}
	return "", nil
}

func (h *fakeHost) hasGroup(name string) bool { _, ok := h.groups[name]; return ok }

// lockPath is the host lock in the test's root.
func (h *fakeHost) lockPath() string { return filepath.Join(h.root, "run/thinkpol/agent.lock") }

// lock takes the host lock as agent.HostLock does, with its error.
func (h *fakeHost) lock() (func(), error) {
	d, err := trusteddir.Make(filepath.Dir(h.lockPath()))
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()
	f, err := trusteddir.Lock(d, filepath.Base(h.lockPath()))
	if errors.Is(err, trusteddir.ErrLocked) {
		return nil, agent.ErrAnotherAgent
	}
	if err != nil {
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}

// installer is an Installer on h for sys, with a binary to copy, a node
// that is ready, the host lock in h's root, and a ClearHost that counts.
func (h *fakeHost) installer(sys System) (Installer, *bytes.Buffer) {
	exe := filepath.Join(h.root, "home", "thinkpol")
	// The host has its manager, and somewhere to copy from.
	for _, dir := range []string{filepath.Dir(exe), filepath.Join(h.root, filepath.Dir(sys.DefinitionPath())),
		filepath.Join(h.root, "run/systemd/system"), filepath.Join(h.root, filepath.Dir(testCrashTrace))} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			h.t.Fatal(err)
		}
	}
	if err := os.WriteFile(exe, []byte("the thinkpol binary"), 0o755); err != nil {
		h.t.Fatal(err)
	}
	var out bytes.Buffer
	return Installer{
		Root: h.root, System: sys, Run: h.run, Executable: exe, Ready: func() (agent.Mode, bool, error) { return agent.ModeDevice, true, nil },
		CrashTrace: testCrashTrace,
		LockHost:   h.lock,
		ClearHost: func() ([]string, error) {
			h.cleared++
			unlock, err := h.lock()
			switch {
			case errors.Is(err, agent.ErrAnotherAgent):
				h.heldWhileCleared++
			case err == nil:
				unlock()
			}
			return nil, nil
		},
		RuntimeDirs: []string{"/run/thinkpol", "/run/thinkpol-api"}, Out: &out,
	}, &out
}

func (h *fakeHost) file(p string) ([]byte, os.FileMode, bool) {
	fi, err := os.Lstat(filepath.Join(h.root, p))
	if err != nil {
		return nil, 0, false
	}
	if !fi.Mode().IsRegular() {
		return nil, fi.Mode(), true
	}
	data, err := os.ReadFile(filepath.Join(h.root, p))
	if err != nil {
		h.t.Fatal(err)
	}
	return data, fi.Mode(), true
}

func TestInstallUnderSystemd(t *testing.T) {
	h := newFakeHost(t)
	in, _ := h.installer(Systemd{})
	ctx := context.Background()
	if err := in.Install(ctx, Options{User: "alice"}); err != nil {
		t.Fatal(err)
	}

	unit, mode, ok := h.file(UnitPath)
	if !ok || mode.Perm() != 0o644 || !bytes.Equal(unit, SystemdUnit(deviceDefinition)) {
		t.Fatalf("the unit (%v, %v):\n%s", ok, mode, unit)
	}
	bin, mode, ok := h.file(BinaryPath)
	if !ok || mode.Perm() != 0o755 || string(bin) != "the thinkpol binary" {
		t.Fatalf("the binary: %v %v %q", ok, mode, bin)
	}
	// systemd read the unit, enabled it and runs the agent from it.
	if !h.enabled || !bytes.Equal(h.unitLoaded, unit) || !bytes.Equal(h.unitRunning, unit) || !slices.Equal(h.groups[Group], []string{"alice"}) {
		t.Fatalf("enabled %v, loaded %q, running %q, group %v", h.enabled, h.unitLoaded, h.unitRunning, h.groups)
	}
	// Installed again (a new binary): restarted on the same unit.
	if err := in.Install(ctx, Options{User: "alice"}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(h.unitRunning, unit) || !slices.Equal(h.groups[Group], []string{"alice"}) {
		t.Fatalf("after a reinstall: running %q, group %v", h.unitRunning, h.groups)
	}
}

// A definition written before connect-on-boot moved to the device's
// settings is replaced, and install says where the setting went.
// An old definition, as the older install wrote it or changed by hand
// too, is told where connect-on-boot went; one changed by hand is also
// warned about.
func TestInstallOverAnOldDefinitionSaysWhereConnectOnBootWent(t *testing.T) {
	for name, tc := range map[string]struct {
		sys     System
		old     []byte
		warning bool
	}{
		"systemd, as written":      {Systemd{}, oldSystemdUnit(BinaryPath, "on"), false},
		"launchd, as written":      {Launchd{}, oldLaunchdPlist(BinaryPath, "off"), false},
		"systemd, changed by hand": {Systemd{}, []byte("[Service]\nExecStart=" + BinaryPath + " up\nEnvironment=THINKPOL_CONNECT_ON_BOOT=on\n"), true},
	} {
		t.Run(name, func(t *testing.T) {
			h := newFakeHost(t)
			in, out := h.installer(tc.sys)
			path := filepath.Join(h.root, tc.sys.DefinitionPath())
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, tc.old, 0o644); err != nil {
				t.Fatal(err)
			}
			if err := in.Install(context.Background(), Options{}); err != nil {
				t.Fatal(err)
			}
			if def, _, _ := h.file(tc.sys.DefinitionPath()); !bytes.Equal(def, tc.sys.Render(deviceDefinition)) {
				t.Fatalf("the definition:\n%s", def)
			}
			said := out.String()
			if !strings.Contains(said, "thinkpol connect-on-boot on") || strings.Contains(said, "warning: ") != tc.warning ||
				tc.warning && !strings.Contains(said, "changed by hand") {
				t.Fatalf("said:\n%s", said)
			}
		})
	}
}

func TestUninstallLeavesNothingOfTheService(t *testing.T) {
	for name, sys := range map[string]System{"systemd": Systemd{}, "launchd": Launchd{}} {
		t.Run(name, func(t *testing.T) {
			h := newFakeHost(t)
			in, out := h.installer(sys)
			ctx := context.Background()
			if err := in.Install(ctx, Options{User: "alice"}); err != nil {
				t.Fatal(err)
			}
			// What a stopped agent leaves, and what it doesn't: a crashed
			// run's route record stays, and is reported.
			for _, f := range []string{"/run/thinkpol/agent.lock", "/run/thinkpol/" + agent.ConnectRecordFile, "/run/thinkpol/netcfg/overlay.lock",
				"/run/thinkpol-api/api.lock", "/run/thinkpol/netcfg/overlay.routes", "/var/lib/thinkpol/node.key", testCrashTrace} {
				if err := os.MkdirAll(filepath.Join(h.root, filepath.Dir(f)), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(h.root, f), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			if err := in.Uninstall(ctx, false); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{sys.DefinitionPath(), BinaryPath, "/run/thinkpol-api", "/run/thinkpol/agent.lock",
				"/run/thinkpol/" + agent.ConnectRecordFile, "/run/thinkpol/netcfg/overlay.lock", testCrashTrace} {
				if _, _, ok := h.file(p); ok {
					t.Errorf("%s is left", p)
				}
			}
			for _, p := range []string{"/run/thinkpol/netcfg/overlay.routes", "/var/lib/thinkpol/node.key"} {
				if _, _, ok := h.file(p); !ok {
					t.Errorf("%s was removed", p)
				}
			}
			if !strings.Contains(out.String(), "overlay.routes") {
				t.Errorf("the record left isn't reported:\n%s", out)
			}
			// A crashed agent's leftovers undone, under the host lock.
			if h.cleared != 1 || h.heldWhileCleared != 1 {
				t.Errorf("ClearHost ran %d times, %d under the lock", h.cleared, h.heldWhileCleared)
			}
			// The group stays: it may be older than the service.
			if !h.hasGroup(Group) || h.loaded || h.overridden || h.unitRunning != nil || h.enabled || h.unitLoaded != nil {
				t.Fatalf("group %v, launchd loaded %v override %v, systemd running %q enabled %v loaded %q",
					h.groups, h.loaded, h.overridden, h.unitRunning, h.enabled, h.unitLoaded)
			}
			if err := in.installed(); !errors.Is(err, ErrNotInstalled) {
				t.Fatalf("the definition after uninstall: %v", err)
			}
			// Uninstalling again finds nothing to do.
			if err := in.Uninstall(ctx, false); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// An agent that holds the host lock (one run by hand, or one the stop
// didn't end) keeps everything it uses: uninstall refuses before it
// removes a lock or clears anything, and install refuses to start a
// service that would only restart against it.
func TestNothingIsTakenFromARunningAgent(t *testing.T) {
	h := newFakeHost(t)
	in, _ := h.installer(Systemd{})
	ctx := context.Background()
	unlock, err := h.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	if err := in.Install(ctx, Options{}); !errors.Is(err, errAgentRuns) {
		t.Fatalf("install: %v", err)
	}
	if _, _, ok := h.file(BinaryPath); ok || h.hasGroup(Group) {
		t.Fatal("install changed something")
	}

	unlock()
	if err := in.Install(ctx, Options{}); err != nil {
		t.Fatal(err)
	}
	unlockAgain, err := h.lock()
	if err != nil {
		t.Fatal(err)
	}
	if err := in.Uninstall(ctx, false); !errors.Is(err, errAgentRuns) {
		t.Fatalf("uninstall: %v", err)
	}
	if _, _, ok := h.file("/run/thinkpol/agent.lock"); !ok || h.cleared != 0 {
		t.Fatalf("the lock file was removed (%v) or the host cleared (%d)", !ok, h.cleared)
	}
	if _, _, ok := h.file(BinaryPath); !ok {
		t.Fatal("the binary was removed")
	}
	unlockAgain()

	// The service stopped by hand and an agent run by hand: the reinstall
	// replaces the binary and the definition (the next boot runs them),
	// stops nothing more and starts nothing, since its service would only
	// restart against the agent's lock.
	if err := in.Install(ctx, Options{}); err != nil {
		t.Fatal(err)
	}
	h.unitRunning = nil // systemctl stop
	byHand, err := h.lock()
	if err != nil {
		t.Fatal(err)
	}
	defer byHand()
	if err := os.WriteFile(in.Executable, []byte("a newer thinkpol"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := in.Install(ctx, Options{}); !errors.Is(err, errAgentRuns) {
		t.Fatalf("reinstall: %v", err)
	}
	if bin, _, _ := h.file(BinaryPath); string(bin) != "a newer thinkpol" || h.unitRunning != nil || !h.enabled {
		t.Fatalf("binary %q, running %q, enabled %v: want the new binary, stopped and still enabled", bin, h.unitRunning, h.enabled)
	}
}

// Every step of a reinstall that can fail runs before the service is
// stopped: one that fails (a user the group can't take) leaves the
// installed service running from its definition and, for systemd,
// enabled.
func TestAFailedReinstallLeavesTheServiceAsItWas(t *testing.T) {
	ctx := context.Background()
	t.Run("systemd", func(t *testing.T) {
		h := newFakeHost(t)
		in, _ := h.installer(Systemd{})
		if err := in.Install(ctx, Options{}); err != nil {
			t.Fatal(err)
		}
		running := h.unitRunning
		oldBin, _, _ := h.file(BinaryPath)
		if err := os.WriteFile(in.Executable, []byte("a newer thinkpol"), 0o755); err != nil {
			t.Fatal(err)
		}
		h.failNext["usermod -a"] = 1
		if err := in.Install(ctx, Options{User: "nosuchuser"}); err == nil {
			t.Fatal("installed")
		}
		if !h.enabled || !bytes.Equal(h.unitRunning, running) {
			t.Fatalf("enabled %v, running %q, want %q", h.enabled, h.unitRunning, running)
		}
		// The group step fails before the binary is replaced: the old
		// definition's next restart runs the binary it was written for.
		if bin, _, _ := h.file(BinaryPath); !bytes.Equal(bin, oldBin) {
			t.Fatalf("binary %q after a failed group step, want %q", bin, oldBin)
		}
	})
	t.Run("launchd", func(t *testing.T) {
		h := newFakeHost(t)
		in, _ := h.installer(Launchd{})
		if err := in.Install(ctx, Options{}); err != nil {
			t.Fatal(err)
		}
		loaded := h.loadedFrom
		h.groups[Group] = nil
		h.failNext["dseditgroup -o"] = 2 // the group calls fail
		if err := in.Install(ctx, Options{User: "nosuchuser"}); err == nil {
			t.Fatal("installed")
		}
		if !h.loaded || !bytes.Equal(h.loadedFrom, loaded) {
			t.Fatalf("loaded %v from %q", h.loaded, h.loadedFrom)
		}
	})
}

// launchd may refuse a bootstrap just after the job it replaces is gone
// (EIO): retried; another refusal isn't.
func TestLaunchdRetriesABootstrapRefusedWithEIO(t *testing.T) {
	h := newFakeHost(t)
	in, _ := h.installer(Launchd{Poll: time.Millisecond})
	ctx := context.Background()
	h.bootstrapEIO = 2
	if err := in.Install(ctx, Options{}); err != nil || !h.loaded {
		t.Fatalf("%v, loaded %v", err, h.loaded)
	}
	h.failNext["launchctl bootstrap"] = 1
	if err := in.Install(ctx, Options{}); err == nil || h.loaded {
		t.Fatalf("%v, loaded %v: want the refusal", err, h.loaded)
	}
}

// A ClearHost that fails stops uninstall before it removes the binary
// that could clear the host again, saying what is left of the service and
// what cleared; -force then completes it, reporting what stays on the
// host.
func TestUninstallStopsOnAFailedClearAndForceCompletesIt(t *testing.T) {
	for _, sys := range []System{Systemd{}, Launchd{}} {
		t.Run(fmt.Sprintf("%T", sys), func(t *testing.T) {
			h := newFakeHost(t)
			in, out := h.installer(sys)
			ctx := context.Background()
			if err := in.Install(ctx, Options{}); err != nil {
				t.Fatal(err)
			}
			// What macOS's resolver cleanup hits on every try: a backup
			// record readBackup rejects.
			stuck := errors.New("dns: the store's backup: illegal base64 data at input byte 4")
			in.ClearHost = func() ([]string, error) {
				return []string{"the space link tp-space0"}, stuck
			}
			err := in.Uninstall(ctx, false)
			if !errors.Is(err, stuck) || !strings.Contains(err.Error(), sys.DefinitionPath()) ||
				!strings.Contains(err.Error(), BinaryPath) || !strings.Contains(err.Error(), "-force") {
				t.Fatalf("got %v", err)
			}
			for _, p := range []string{sys.DefinitionPath(), BinaryPath} {
				if _, _, ok := h.file(p); !ok {
					t.Fatalf("%s was removed", p)
				}
			}
			if !strings.Contains(out.String(), "tp-space0") {
				t.Errorf("what was undone isn't reported:\n%s", out)
			}

			out.Reset()
			if err := in.Uninstall(ctx, true); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{sys.DefinitionPath(), BinaryPath} {
				if _, _, ok := h.file(p); ok {
					t.Errorf("%s is left", p)
				}
			}
			if !strings.Contains(out.String(), "warning: left on the host") || !strings.Contains(out.String(), stuck.Error()) {
				t.Errorf("what is left on the host isn't reported:\n%s", out)
			}
			if err := in.installed(); !errors.Is(err, ErrNotInstalled) {
				t.Fatalf("the definition after a forced uninstall: %v", err)
			}

			// Nothing on disk: nothing for -force to keep, so uninstall
			// stays idempotent, the failure a warning.
			out.Reset()
			if err := in.Uninstall(ctx, false); err != nil {
				t.Fatalf("with nothing installed: %v", err)
			}
			if !strings.Contains(out.String(), "warning: left on the host") || !strings.Contains(out.String(), stuck.Error()) {
				t.Errorf("what is left on the host isn't reported:\n%s", out)
			}
		})
	}
}

func TestInstallUnderLaunchd(t *testing.T) {
	h := newFakeHost(t)
	in, _ := h.installer(Launchd{})
	ctx := context.Background()
	if err := in.Install(ctx, Options{User: "alice"}); err != nil {
		t.Fatal(err)
	}
	plist, mode, ok := h.file(PlistPath)
	if !ok || mode.Perm() != 0o644 || !bytes.Equal(plist, LaunchdPlist(deviceDefinition)) {
		t.Fatalf("the plist (%v, %v):\n%s", ok, mode, plist)
	}
	// Loaded from the plist, and no override written on a clean host.
	if !h.loaded || !bytes.Equal(h.loadedFrom, plist) || h.overridden || !slices.Equal(h.groups[Group], []string{"alice"}) {
		t.Fatalf("loaded %v, override %v, group %v", h.loaded, h.overridden, h.groups)
	}
	// Installed again over the running daemon, which launchd still shows
	// for a while after the bootout: Start waits, then loads the new plist.
	// alice, a member already, isn't added twice.
	h.goneAfter = 3
	if err := in.Install(ctx, Options{User: "alice"}); err != nil {
		t.Fatal(err)
	}
	if !h.loaded || !bytes.Equal(h.loadedFrom, plist) || !slices.Equal(h.groups[Group], []string{"alice"}) {
		t.Fatalf("reinstalled: loaded %v, group %v, from\n%s", h.loaded, h.groups, h.loadedFrom)
	}
	// A daemon someone disabled is enabled again.
	h.overridden, h.disabled = true, true
	if err := in.Install(ctx, Options{}); err != nil || !h.loaded || h.disabled {
		t.Fatalf("a disabled daemon: %v, loaded %v, disabled %v", err, h.loaded, h.disabled)
	}
}

// launchd keeps showing a booted-out daemon until its agent exits; a stop
// that outlasts the wait, or a bootout that fails with the daemon still
// there, is an error, and nothing is bootstrapped over it.
func TestLaunchdWaitsForTheDaemonToGo(t *testing.T) {
	h := newFakeHost(t)
	l := Launchd{StopWait: 50 * time.Millisecond, Poll: time.Millisecond}
	in, _ := h.installer(l)
	ctx := context.Background()
	if err := in.Install(ctx, Options{}); err != nil {
		t.Fatal(err)
	}
	h.goneAfter = 1 << 30
	if err := in.Install(ctx, Options{}); err == nil || !strings.Contains(err.Error(), "still has") {
		t.Fatalf("got %v", err)
	}
	if h.loaded {
		t.Fatal("bootstrapped over a daemon still going")
	}

	h = newFakeHost(t)
	in, _ = h.installer(l)
	if err := in.Install(ctx, Options{}); err != nil {
		t.Fatal(err)
	}
	h.failNext["launchctl bootout"] = 1
	if err := in.Uninstall(ctx, false); err == nil || !strings.Contains(err.Error(), "bootout") {
		t.Fatalf("got %v", err)
	}
	if _, _, ok := h.file(PlistPath); !ok {
		t.Fatal("the plist was removed under a daemon still loaded")
	}

	// A bootout that says "in progress" while the daemon goes all the
	// same: the wait decides, and the reinstall goes on.
	h.failNext["launchctl bootout"] = 0
	h.bootoutFails, h.goneAfter = true, 2
	if err := in.Install(ctx, Options{}); err != nil || !h.loaded {
		t.Fatalf("after a slow bootout: %v, loaded %v", err, h.loaded)
	}
	// A print that fails for another reason isn't "gone": the stop fails,
	// and uninstall leaves the plist and the binary.
	h.bootoutFails, h.printFails = false, true
	if err := in.Uninstall(ctx, false); err == nil || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("got %v", err)
	}
	if _, _, ok := h.file(PlistPath); !ok {
		t.Fatal("the plist was removed while launchd couldn't be asked")
	}
	if _, _, ok := h.file(BinaryPath); !ok {
		t.Fatal("the binary was removed while launchd couldn't be asked")
	}
}

func TestInstallRefusesBeforeChangingAnything(t *testing.T) {
	for name, change := range map[string]func(*fakeHost, *Installer){
		"a node that can't run": func(_ *fakeHost, in *Installer) {
			in.Ready = func() (agent.Mode, bool, error) { return "", false, errors.New("no node.key") }
		},
		"a host without systemd": func(h *fakeHost, _ *Installer) {
			if err := os.Remove(filepath.Join(h.root, "run/systemd/system")); err != nil {
				h.t.Fatal(err)
			}
		},
		"a binary directory others can write to": func(h *fakeHost, _ *Installer) {
			dir := filepath.Join(h.root, filepath.Dir(BinaryPath))
			if err := os.MkdirAll(dir, 0o755); err != nil {
				h.t.Fatal(err)
			}
			if err := os.Chmod(dir, 0o777); err != nil {
				h.t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newFakeHost(t)
			in, _ := h.installer(Systemd{})
			change(h, &in)
			err := in.Install(context.Background(), Options{User: "alice"})
			if err == nil {
				t.Fatal("installed")
			}
			want := map[string]string{"a node that can't run": "no node.key", "a host without systemd": "doesn't run systemd",
				"a binary directory others can write to": "others can change"}[name]
			if !strings.Contains(err.Error(), want) {
				t.Fatalf("got %v, want %q", err, want)
			}
			if _, _, ok := h.file(BinaryPath); ok || h.hasGroup(Group) || h.unitRunning != nil {
				t.Fatal("installed something")
			}
		})
	}
}

// Root's service never runs a binary a user could change: a symlink at
// BinaryPath to the running binary, or that binary writable by others,
// is replaced with a copy; root's own file there, the running one, stays.
func TestInstallReplacesABinaryOthersCouldChange(t *testing.T) {
	ctx := context.Background()
	t.Run("a symlink to the running binary", func(t *testing.T) {
		h := newFakeHost(t)
		in, _ := h.installer(Systemd{})
		dst := filepath.Join(h.root, BinaryPath)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(in.Executable, dst); err != nil {
			t.Fatal(err)
		}
		if err := in.Install(ctx, Options{}); err != nil {
			t.Fatal(err)
		}
		if data, mode, _ := h.file(BinaryPath); !mode.IsRegular() || mode.Perm() != 0o755 || string(data) != "the thinkpol binary" {
			t.Fatalf("the binary: %v %q", mode, data)
		}
	})
	t.Run("the running binary, writable by others", func(t *testing.T) {
		h := newFakeHost(t)
		in, _ := h.installer(Systemd{})
		dst := filepath.Join(h.root, BinaryPath)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Link(in.Executable, dst); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(in.Executable, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := in.Install(ctx, Options{}); err != nil {
			t.Fatal(err)
		}
		cur, _ := os.Lstat(dst)
		src, _ := os.Stat(in.Executable)
		if os.SameFile(cur, src) || cur.Mode().Perm() != 0o755 {
			t.Fatalf("still the user's file, or %v", cur.Mode())
		}
	})
	t.Run("root's own, installed and running", func(t *testing.T) {
		h := newFakeHost(t)
		in, _ := h.installer(Systemd{})
		if err := in.Install(ctx, Options{}); err != nil {
			t.Fatal(err)
		}
		in.Executable = filepath.Join(h.root, BinaryPath)
		before, _ := os.Lstat(in.Executable)
		if err := in.Install(ctx, Options{}); err != nil {
			t.Fatal(err)
		}
		after, _ := os.Lstat(in.Executable)
		if !os.SameFile(before, after) {
			t.Fatal("root's own binary was copied over itself")
		}
		// One that isn't 0755 is replaced with one that is.
		if err := os.Chmod(in.Executable, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := in.Install(ctx, Options{}); err != nil {
			t.Fatal(err)
		}
		if cur, _ := os.Lstat(in.Executable); os.SameFile(after, cur) || cur.Mode().Perm() != 0o755 {
			t.Fatalf("kept a binary %v", cur.Mode())
		}
	})
}

func TestADefinitionChangedByHandIsReported(t *testing.T) {
	h := newFakeHost(t)
	in, out := h.installer(Systemd{})
	ctx := context.Background()
	if err := in.Install(ctx, Options{}); err != nil {
		t.Fatal(err)
	}
	unit, _, _ := h.file(UnitPath)
	edited := bytes.Replace(unit, []byte("up -service\n"), []byte("up -service -log-level debug\n"), 1)
	if err := os.WriteFile(filepath.Join(h.root, UnitPath), edited, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := in.installed(); !errors.Is(err, ErrDefinitionChanged) {
		t.Fatalf("got %v", err)
	}
	// Installed over it: anew, with a warning.
	if err := in.Install(ctx, Options{}); err != nil {
		t.Fatal(err)
	}
	if now, _, _ := h.file(UnitPath); !bytes.Equal(now, unit) || !strings.Contains(out.String(), "warning: ") {
		t.Fatalf("the unit:\n%s\nsaid\n%s", now, out)
	}
}

// A device's definition names its crash trace, which its install makes
// anew, empty and 0600, before the service starts; a server's names none,
// and its install removes a trace a device left (PRD S2), after the old
// service stopped (its agent may write one as it dies). A node whose mode
// changed is installed anew without a warning: its definition wasn't
// changed by hand. A node of unknown kind is installed as a server, and
// told.
func TestOnlyADevicesDefinitionKeepsACrashTrace(t *testing.T) {
	for name, sys := range map[string]System{"systemd": Systemd{}, "launchd": Launchd{}} {
		t.Run(name, func(t *testing.T) {
			h := newFakeHost(t)
			in, out := h.installer(sys)
			ctx := context.Background()
			trace := filepath.Join(h.root, testCrashTrace)
			// Someone else's file, world-readable, is there before.
			if err := os.WriteFile(trace, []byte("planted\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := in.Install(ctx, Options{}); err != nil {
				t.Fatal(err)
			}
			def, _, _ := h.file(sys.DefinitionPath())
			if !bytes.Equal(def, sys.Render(deviceDefinition)) || !bytes.Contains(def, []byte(testCrashTrace)) {
				t.Fatalf("a device's definition:\n%s", def)
			}
			if at := h.traceAtStart; at == nil || at.Mode() != 0o600 || at.Size() != 0 {
				t.Fatalf("the crash trace at the start: %v", at)
			}

			// The device's agent crashed and left its trace; it crashes
			// again as the server's install stops it.
			if err := os.WriteFile(trace, []byte("panic: boom\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			h.crashOnStop = true
			in.Ready = func() (agent.Mode, bool, error) { return agent.ModeServer, true, nil }
			if err := in.Install(ctx, Options{}); err != nil {
				t.Fatal(err)
			}
			def, _, _ = h.file(sys.DefinitionPath())
			if !bytes.Equal(def, sys.Render(Definition{Binary: BinaryPath})) || bytes.Contains(def, []byte(testCrashTrace)) {
				t.Fatalf("a server's definition:\n%s", def)
			}
			if _, _, ok := h.file(testCrashTrace); ok || h.traceAtStart != nil {
				t.Error("a server's install left the crash trace")
			}
			if strings.Contains(out.String(), "warning: ") || !strings.Contains(out.String(), "removed the crash trace") {
				t.Errorf("said:\n%s", out)
			}
			h.crashOnStop = false

			in.Ready = func() (agent.Mode, bool, error) { return agent.ModeDevice, true, nil }
			out.Reset()
			if err := in.Install(ctx, Options{}); err != nil {
				t.Fatal(err)
			}
			if def, _, _ = h.file(sys.DefinitionPath()); !bytes.Equal(def, sys.Render(deviceDefinition)) || strings.Contains(out.String(), "warning: ") {
				t.Fatalf("a device's definition again:\n%s\nsaid\n%s", def, out)
			}

			in.Ready = func() (agent.Mode, bool, error) { return agent.ModeServer, false, nil }
			out.Reset()
			if err := in.Install(ctx, Options{}); err != nil {
				t.Fatal(err)
			}
			if def, _, _ = h.file(sys.DefinitionPath()); !bytes.Equal(def, sys.Render(Definition{Binary: BinaryPath})) || !strings.Contains(out.String(), "kind isn't known") {
				t.Fatalf("an unknown kind's definition:\n%s\nsaid\n%s", def, out)
			}
		})
	}
}

// The group install makes is the one the agent's local API admits.
func TestTheGroupIsTheLocalAPIsDefault(t *testing.T) {
	if _, ok := os.LookupEnv("THINKPOL_API_GROUP"); ok {
		t.Skip("THINKPOL_API_GROUP is set")
	}
	cfg, err := agent.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIGroup != Group {
		t.Fatalf("the agent's default group %q, install's %q", cfg.APIGroup, Group)
	}
}

// A unit file an install wrote and then died before starting (on disk,
// never daemon-reloaded) doesn't block the next install, which starts the
// service, nor uninstall: systemd 252 loads it for the stop (seen in the
// lab), and one that doesn't answers "not loaded" (exit 5), read as
// stopped. A stop that fails otherwise still stops the install.
func TestANeverLoadedUnitCountsAsStopped(t *testing.T) {
	ctx := context.Background()
	unit := SystemdUnit(deviceDefinition)
	for _, old := range []bool{false, true} {
		h := newFakeHost(t)
		h.oldSystemd = old
		in, _ := h.installer(Systemd{})
		if err := os.WriteFile(filepath.Join(h.root, UnitPath), unit, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := in.Install(ctx, Options{}); err != nil {
			t.Fatalf("old systemd %v: %v", old, err)
		}
		if !h.enabled || !bytes.Equal(h.unitRunning, unit) {
			t.Fatalf("old systemd %v: enabled %v, running %q", old, h.enabled, h.unitRunning)
		}

		h = newFakeHost(t)
		h.oldSystemd = old
		in, _ = h.installer(Systemd{})
		if err := os.WriteFile(filepath.Join(h.root, UnitPath), unit, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := in.Uninstall(ctx, false); err != nil {
			t.Fatalf("old systemd %v: %v", old, err)
		}
		if _, _, ok := h.file(UnitPath); ok {
			t.Fatal("the unit is left")
		}
	}

	h := newFakeHost(t)
	in, _ := h.installer(Systemd{})
	if err := in.Install(ctx, Options{}); err != nil {
		t.Fatal(err)
	}
	h.failNext["systemctl stop"] = 1
	if err := in.Install(ctx, Options{}); err == nil || !strings.Contains(err.Error(), "the new binary and definition are on disk; stopping the installed service failed") {
		t.Fatalf("a stop that failed: %v", err)
	}
}

// A start that fails says what install knows, first, before the
// manager's own words: whether it stopped the installed service, that the
// definition is on disk, and what the manager reports now; never a state
// it doesn't know.
func TestAFailedStartSaysWhatItLeft(t *testing.T) {
	ctx := context.Background()
	stateFirst := func(t *testing.T, err error, want ...string) {
		t.Helper()
		if err == nil {
			t.Fatal("installed")
		}
		msg := err.Error()
		for _, w := range want {
			if !strings.Contains(msg, w) {
				t.Errorf("no %q in %q", w, msg)
			}
		}
		if i, j := strings.Index(msg, want[len(want)-1]), strings.Index(msg, "failing on purpose"); i < 0 || j < 0 || i > j {
			t.Errorf("the state isn't before the manager's error: %q", msg)
		}
	}
	t.Run("systemd", func(t *testing.T) {
		h := newFakeHost(t)
		in, _ := h.installer(Systemd{})
		h.failNext["systemctl restart"] = 1
		err := in.Install(ctx, Options{})
		stateFirst(t, err, "the definition is on disk", "systemd reports the unit enabled and inactive")
		if strings.Contains(err.Error(), "launchd") || strings.Contains(err.Error(), "stopped") {
			t.Errorf("says what it doesn't know: %q", err)
		}
		if err := in.Install(ctx, Options{}); err != nil {
			t.Fatal(err)
		}
		h.failNext["systemctl restart"] = 1
		stateFirst(t, in.Install(ctx, Options{}), "the installed service was stopped", "systemd reports the unit enabled and inactive")

		// A unit never enabled (written by an install that died), whose
		// daemon-reload fails: not enabled, and not said to be.
		h = newFakeHost(t)
		in, _ = h.installer(Systemd{})
		if err := os.WriteFile(filepath.Join(h.root, UnitPath), SystemdUnit(deviceDefinition), 0o644); err != nil {
			t.Fatal(err)
		}
		h.failNext["systemctl daemon-reload"] = 1
		err = in.Install(ctx, Options{})
		stateFirst(t, err, "systemd reports the unit disabled and inactive")
		if strings.Contains(err.Error(), " enabled") {
			t.Errorf("says enabled: %q", err)
		}
	})
	t.Run("launchd", func(t *testing.T) {
		h := newFakeHost(t)
		in, _ := h.installer(Launchd{})
		h.failNext["launchctl bootstrap"] = 1
		err := in.Install(ctx, Options{})
		stateFirst(t, err, "the definition is on disk", "launchd doesn't have the daemon loaded, no override disables it")
		if strings.Contains(err.Error(), "systemd") {
			t.Errorf("names systemd: %q", err)
		}
	})
}

// What decides a tool's answer is its exit status, as runTool wraps a real
// *exec.ExitError; the text counts only without one.
func TestTheExitStatusDecides(t *testing.T) {
	wrap := func(code int) error { return fmt.Errorf("tool: %w: stderr", exitError(t, code)) }
	for name, got := range map[string]bool{
		"not loaded, exit 5":            notLoaded("", wrap(5)),
		"not loaded text, no exit code": notLoaded("Unit x not loaded.", errors.New("tool failed")),
		"no such service, exit 113":     noSuchService("", wrap(113)),
		"EIO, exit 5":                   inputOutputError("", wrap(5)),
	} {
		if !got {
			t.Errorf("%s: false", name)
		}
	}
	if notLoaded("Unit x not loaded.", wrap(4)) {
		t.Error("the text read as not loaded under exit 4")
	}
}

// A print that fails after a bootstrap refused with EIO reports both.
func TestAnEIOThenAFailedPrintSaysBoth(t *testing.T) {
	h := newFakeHost(t)
	in, _ := h.installer(Launchd{Poll: time.Millisecond})
	h.bootstrapEIO, h.printFailsAfterEIO = 1, true
	err := in.Install(context.Background(), Options{})
	if err == nil || !strings.Contains(err.Error(), "Input/output error") || !strings.Contains(err.Error(), "not permitted") {
		t.Fatalf("got %v", err)
	}
}

// launchd may say EIO of a bootstrap that loaded the job: a job it then
// shows is started, not bootstrapped again.
func TestLaunchdTakesAnEIOBootstrapThatLoadedTheJob(t *testing.T) {
	h := newFakeHost(t)
	in, _ := h.installer(Launchd{Poll: time.Millisecond})
	h.bootstrapEIOLoaded = 1
	if err := in.Install(context.Background(), Options{}); err != nil || !h.loaded {
		t.Fatalf("%v, loaded %v", err, h.loaded)
	}
}

// systemd's state is read only from the words systemd answers with, on
// the output's last line; anything else is said to be unread, never
// passed off as a state.
func TestSystemdStateIsOnlyWhatSystemdSaid(t *testing.T) {
	answers := func(enabled, active string, enabledErr, activeErr error) Runner {
		return func(_ context.Context, tool string, args ...string) (string, error) {
			if tool != "systemctl" || len(args) != 2 || args[1] != UnitName {
				return "", fmt.Errorf("unexpected %s %v", tool, args)
			}
			if args[0] == "is-enabled" {
				return enabled, enabledErr
			}
			return active, activeErr
		}
	}
	bus := errors.New("exit status 1")
	missing := errors.New("systemctl: not found in /usr/sbin, /usr/bin, /sbin, /bin")
	for name, tc := range map[string]struct {
		run  Runner
		want string
	}{
		"no bus": {answers("Failed to get unit file state for thinkpol.service: Failed to connect to bus: No such file or directory\n",
			"Failed to connect to bus: No such file or directory\n", bus, bus), "systemd couldn't be asked about the unit"},
		"no systemctl": {answers("", "", missing, missing), "systemd couldn't be asked about the unit"},
		"a warning first": {answers("Warning: The unit file, source configuration file or drop-ins of thinkpol.service changed on disk. Run 'systemctl daemon-reload' to reload units.\nenabled\n",
			"inactive\n", nil, exitError(t, 3)), "systemd reports the unit enabled and inactive"},
		"activating": {answers("enabled\n", "activating\n", nil, exitError(t, 3)), "systemd reports the unit enabled and activating (Restart=always retries it)"},
		"one unread": {answers("disabled\n", "Failed to connect to bus: No such file or directory\n", exitError(t, 1), bus),
			"systemd reports the unit disabled; whether it runs couldn't be read"},
	} {
		if got := (Systemd{}).State(context.Background(), tc.run); got != tc.want {
			t.Errorf("%s: %q, want %q", name, got, tc.want)
		}
	}
}

// The state is asked within a short wait of its own: a wedged manager
// doesn't hold the real error back, and an install whose context ended
// still asks.
func TestTheStateHasAWaitOfItsOwn(t *testing.T) {
	wedged := Installer{System: Systemd{}, Run: func(ctx context.Context, _ string, _ ...string) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	}}
	start := time.Now()
	if got := wedged.leftAfter(context.Background(), false); !strings.Contains(got, "couldn't be asked") || time.Since(start) > 3*stateWait {
		t.Fatalf("%q after %v", got, time.Since(start))
	}
	answering := Installer{System: Systemd{}, Run: func(ctx context.Context, _ string, args ...string) (string, error) {
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
		if args[0] == "is-enabled" {
			return "enabled\n", nil
		}
		return "inactive\n", nil
	}}
	ended, cancel := context.WithCancel(context.Background())
	cancel()
	if got := answering.leftAfter(ended, true); !strings.Contains(got, "systemd reports the unit enabled and inactive") {
		t.Fatalf("with the install's context ended: %q", got)
	}
}
