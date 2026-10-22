//go:build linux || darwin

package service

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
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
	// bootstrapEIO: bootstraps refused with launchd's EIO before one is
	// taken.
	bootstrapEIO int
	// cleared counts ClearHost's runs, and heldWhileCleared whether the
	// host lock was held at each.
	cleared, heldWhileCleared int
}

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
	case slices.Equal(args, []string{"reset-failed", UnitName}):
	default:
		return "", fmt.Errorf("systemctl %v: refused", args)
	}
	return "", nil
}

func (h *fakeHost) launchctl(args []string) (string, error) {
	switch {
	case slices.Equal(args, []string{"print", target}) && h.printFails:
		return "", errors.New("launchctl: Operation not permitted")
	case slices.Equal(args, []string{"print", target}):
		if h.booting > 0 {
			h.booting--
			return "", nil
		}
		if !h.loaded {
			return "", errors.New("could not find service")
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
	case slices.Equal(args, []string{"bootstrap", "system", PlistPath}) && h.bootstrapEIO > 0:
		h.bootstrapEIO--
		return "Bootstrap failed: 5: Input/output error", errors.New("exit status 5")
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
		filepath.Join(h.root, "run/systemd/system")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			h.t.Fatal(err)
		}
	}
	if err := os.WriteFile(exe, []byte("the thinkpol binary"), 0o755); err != nil {
		h.t.Fatal(err)
	}
	var out bytes.Buffer
	return Installer{
		Root: h.root, System: sys, Run: h.run, Executable: exe, Ready: func() error { return nil },
		LockHost: h.lock,
		ClearHost: func() error {
			h.cleared++
			unlock, err := h.lock()
			switch {
			case errors.Is(err, agent.ErrAnotherAgent):
				h.heldWhileCleared++
			case err == nil:
				unlock()
			}
			return nil
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

var on, off = true, false

func TestInstallUnderSystemd(t *testing.T) {
	h := newFakeHost(t)
	in, _ := h.installer(Systemd{})
	ctx := context.Background()
	if err := in.Install(ctx, Options{User: "alice"}); err != nil {
		t.Fatal(err)
	}

	unit, mode, ok := h.file(UnitPath)
	if !ok || mode.Perm() != 0o644 || !bytes.Equal(unit, SystemdUnit(Definition{Binary: BinaryPath})) {
		t.Fatalf("the unit (%v, %v):\n%s", ok, mode, unit)
	}
	if !bytes.Contains(unit, []byte("Environment=THINKPOL_CONNECT_ON_BOOT=off\n")) {
		t.Fatalf("connect-on-boot isn't off by default:\n%s", unit)
	}
	bin, mode, ok := h.file(BinaryPath)
	if !ok || mode.Perm() != 0o755 || string(bin) != "the thinkpol binary" {
		t.Fatalf("the binary: %v %v %q", ok, mode, bin)
	}
	// systemd read the unit, enabled it and runs the agent from it.
	if !h.enabled || !bytes.Equal(h.unitLoaded, unit) || !bytes.Equal(h.unitRunning, unit) || !slices.Equal(h.groups[Group], []string{"alice"}) {
		t.Fatalf("enabled %v, loaded %q, running %q, group %v", h.enabled, h.unitLoaded, h.unitRunning, h.groups)
	}
	if c, err := in.ConnectOnBoot(); err != nil || c {
		t.Fatalf("connect-on-boot: %v %v", c, err)
	}

	// The toggle: systemd has the new unit for the next start, the running
	// agent isn't restarted.
	if err := in.SetConnectOnBoot(ctx, true); err != nil {
		t.Fatal(err)
	}
	toggled, _, _ := h.file(UnitPath)
	if c, err := in.ConnectOnBoot(); err != nil || !c || !bytes.Equal(h.unitLoaded, toggled) || !bytes.Equal(h.unitRunning, unit) {
		t.Fatalf("connect-on-boot %v %v, loaded %q, running %q", c, err, h.unitLoaded, h.unitRunning)
	}
	// Installed again (a new binary): restarted on the unit, the toggle
	// kept unless the install sets it.
	if err := in.Install(ctx, Options{User: "alice"}); err != nil {
		t.Fatal(err)
	}
	if c, _ := in.ConnectOnBoot(); !c || !bytes.Equal(h.unitRunning, toggled) || !slices.Equal(h.groups[Group], []string{"alice"}) {
		t.Fatalf("after a reinstall: connect-on-boot %v, running %q, group %v", c, h.unitRunning, h.groups)
	}
	if err := in.Install(ctx, Options{ConnectOnBoot: &off}); err != nil {
		t.Fatal(err)
	}
	if c, _ := in.ConnectOnBoot(); c {
		t.Fatal("install -connect-on-boot=false left it on")
	}
}

func TestUninstallLeavesNothingOfTheService(t *testing.T) {
	for name, sys := range map[string]System{"systemd": Systemd{}, "launchd": Launchd{}} {
		t.Run(name, func(t *testing.T) {
			h := newFakeHost(t)
			in, out := h.installer(sys)
			ctx := context.Background()
			if err := in.Install(ctx, Options{User: "alice", ConnectOnBoot: &on}); err != nil {
				t.Fatal(err)
			}
			// What a stopped agent leaves, and what it doesn't: a crashed
			// run's route record stays, and is reported.
			for _, f := range []string{"/run/thinkpol/agent.lock", "/run/thinkpol/" + agent.ConnectRecordFile, "/run/thinkpol/netcfg/overlay.lock",
				"/run/thinkpol-api/api.lock", "/run/thinkpol/netcfg/overlay.routes", "/var/lib/thinkpol/node.key"} {
				if err := os.MkdirAll(filepath.Join(h.root, filepath.Dir(f)), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(h.root, f), nil, 0o600); err != nil {
					t.Fatal(err)
				}
			}

			if err := in.Uninstall(ctx); err != nil {
				t.Fatal(err)
			}
			for _, p := range []string{sys.DefinitionPath(), BinaryPath, "/run/thinkpol-api", "/run/thinkpol/agent.lock",
				"/run/thinkpol/" + agent.ConnectRecordFile, "/run/thinkpol/netcfg/overlay.lock"} {
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
			if _, err := in.ConnectOnBoot(); !errors.Is(err, ErrNotInstalled) {
				t.Fatalf("connect-on-boot after uninstall: %v", err)
			}
			// Uninstalling again finds nothing to do.
			if err := in.Uninstall(ctx); err != nil {
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
	if err := in.Uninstall(ctx); !errors.Is(err, errAgentRuns) {
		t.Fatalf("uninstall: %v", err)
	}
	if _, _, ok := h.file("/run/thinkpol/agent.lock"); !ok || h.cleared != 0 {
		t.Fatalf("the lock file was removed (%v) or the host cleared (%d)", !ok, h.cleared)
	}
	if _, _, ok := h.file(BinaryPath); !ok {
		t.Fatal("the binary was removed")
	}
	unlockAgain()

	// The service stopped by hand and an agent run by hand: a reinstall
	// stops nothing more, replaces nothing and starts nothing, since its
	// service would only restart against the agent's lock.
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
	if h.unitRunning != nil || !h.enabled {
		t.Fatalf("running %q, enabled %v: want stopped and still enabled", h.unitRunning, h.enabled)
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
		h.failNext["usermod -a"] = 1
		if err := in.Install(ctx, Options{User: "nosuchuser", ConnectOnBoot: &on}); err == nil {
			t.Fatal("installed")
		}
		if !h.enabled || !bytes.Equal(h.unitRunning, running) {
			t.Fatalf("enabled %v, running %q, want %q", h.enabled, h.unitRunning, running)
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
		if err := in.Install(ctx, Options{User: "nosuchuser", ConnectOnBoot: &on}); err == nil {
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
// that could clear the host again.
func TestUninstallKeepsTheBinaryWhileTheHostIsntClear(t *testing.T) {
	h := newFakeHost(t)
	in, _ := h.installer(Systemd{})
	ctx := context.Background()
	if err := in.Install(ctx, Options{}); err != nil {
		t.Fatal(err)
	}
	in.ClearHost = func() error { return errors.New("routes stuck") }
	if err := in.Uninstall(ctx); err == nil || !strings.Contains(err.Error(), "routes stuck") {
		t.Fatalf("got %v", err)
	}
	if _, _, ok := h.file(BinaryPath); !ok {
		t.Fatal("the binary was removed")
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
	if !ok || mode.Perm() != 0o644 || !bytes.Equal(plist, LaunchdPlist(Definition{Binary: BinaryPath})) {
		t.Fatalf("the plist (%v, %v):\n%s", ok, mode, plist)
	}
	// Loaded from the plist, and no override written on a clean host.
	if !h.loaded || !bytes.Equal(h.loadedFrom, plist) || h.overridden || !slices.Equal(h.groups[Group], []string{"alice"}) {
		t.Fatalf("loaded %v, override %v, group %v", h.loaded, h.overridden, h.groups)
	}
	// The toggle is for the next boot: the loaded daemon keeps its plist.
	if err := in.SetConnectOnBoot(ctx, true); err != nil {
		t.Fatal(err)
	}
	if c, err := in.ConnectOnBoot(); err != nil || !c || !bytes.Equal(h.loadedFrom, plist) {
		t.Fatalf("connect-on-boot %v %v", c, err)
	}
	// Installed again over the running daemon, which launchd still shows
	// for a while after the bootout: Start waits, then loads the new plist.
	// alice, a member already, isn't added twice.
	h.goneAfter = 3
	if err := in.Install(ctx, Options{User: "alice"}); err != nil {
		t.Fatal(err)
	}
	if !h.loaded || !bytes.Contains(h.loadedFrom, []byte("<string>on</string>")) || !slices.Equal(h.groups[Group], []string{"alice"}) {
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
	if err := in.Uninstall(ctx); err == nil || !strings.Contains(err.Error(), "bootout") {
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
	if err := in.Uninstall(ctx); err == nil || !strings.Contains(err.Error(), "not permitted") {
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
			in.Ready = func() error { return errors.New("no node.key") }
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
	if err := in.Install(ctx, Options{ConnectOnBoot: &on}); err != nil {
		t.Fatal(err)
	}
	unit, _, _ := h.file(UnitPath)
	edited := bytes.Replace(unit, []byte("up\n"), []byte("up -log-level debug\n"), 1)
	if err := os.WriteFile(filepath.Join(h.root, UnitPath), edited, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := in.SetConnectOnBoot(ctx, true); !errors.Is(err, ErrDefinitionChanged) {
		t.Fatalf("got %v", err)
	}
	if now, _, _ := h.file(UnitPath); !bytes.Equal(now, edited) {
		t.Fatal("the edited unit was rewritten")
	}
	// Installed over it: anew, with a warning that connect-on-boot is off.
	if err := in.Install(ctx, Options{}); err != nil {
		t.Fatal(err)
	}
	if c, err := in.ConnectOnBoot(); err != nil || c || !strings.Contains(out.String(), "warning: ") {
		t.Fatalf("connect-on-boot %v %v, said\n%s", c, err, out)
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

func TestConnectOnBootIsSpelledOnOrOff(t *testing.T) {
	for in, want := range map[string]string{"": "nil", "on": "true", "off": "false", "yes": "error", "true": "error", "ON": "error"} {
		got, err := ParseOnOff(in)
		s := "error"
		switch {
		case err == nil && got == nil:
			s = "nil"
		case err == nil:
			s = fmt.Sprint(*got)
		}
		if s != want {
			t.Errorf("%q: %s, want %s", in, s, want)
		}
	}
}
