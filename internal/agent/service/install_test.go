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
)

// fakeHost is a host's service manager and groups, in memory: what the
// tools' runs leave, for tests to check the state rather than the calls.
type fakeHost struct {
	t    *testing.T
	root string

	mu sync.Mutex
	// groups and their members.
	groups map[string][]string
	// systemd: units enabled, and how often each was (re)started; reloads
	// counts daemon-reloads.
	enabled  map[string]bool
	active   map[string]bool
	starts   map[string]int
	reloads  int
	failNext map[string]int // tool+" "+first arg: fail that many runs
	// launchd: the daemon loaded, and from which plist (read when it was
	// bootstrapped).
	loaded     bool
	loadedFrom []byte
	disabled   bool
}

func newFakeHost(t *testing.T) *fakeHost {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &fakeHost{t: t, root: root, groups: map[string][]string{}, enabled: map[string]bool{},
		active: map[string]bool{}, starts: map[string]int{}, failNext: map[string]int{}}
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
	case "groupadd", "usermod", "getent", "groupdel", "dseditgroup":
		return h.group(tool, args)
	}
	h.t.Errorf("unexpected tool %s %v", tool, args)
	return "", errors.New("no such tool")
}

func (h *fakeHost) systemctl(args []string) (string, error) {
	unitFile := func(u string) bool {
		_, err := os.Stat(filepath.Join(h.root, "/etc/systemd/system", u))
		return err == nil
	}
	switch {
	case slices.Equal(args, []string{"daemon-reload"}):
		h.reloads++
	case len(args) == 2 && args[0] == "enable" && unitFile(args[1]):
		h.enabled[args[1]] = true
	case len(args) == 2 && args[0] == "restart" && unitFile(args[1]):
		h.active[args[1]], h.starts[args[1]] = true, h.starts[args[1]]+1
	case len(args) == 3 && args[0] == "disable" && args[1] == "--now" && unitFile(args[2]):
		h.enabled[args[2]], h.active[args[2]] = false, false
	case len(args) == 2 && args[0] == "reset-failed":
	default:
		return "", fmt.Errorf("systemctl %v: refused", args)
	}
	return "", nil
}

func (h *fakeHost) launchctl(args []string) (string, error) {
	switch {
	case slices.Equal(args, []string{"bootout", target}) && h.loaded:
		h.loaded, h.loadedFrom = false, nil
	case slices.Equal(args, []string{"enable", target}):
		h.disabled = false
	case slices.Equal(args, []string{"bootstrap", "system", PlistPath}) && !h.loaded && !h.disabled:
		data, err := os.ReadFile(filepath.Join(h.root, PlistPath))
		if err != nil {
			return "", err
		}
		h.loaded, h.loadedFrom = true, data
	case slices.Equal(args, []string{"print", target}) && h.loaded:
	default:
		return "", fmt.Errorf("launchctl %v: refused", args)
	}
	return "", nil
}

func (h *fakeHost) group(tool string, args []string) (string, error) {
	name := args[len(args)-1]
	_, exists := h.groups[name]
	switch {
	case tool == "groupadd" && slices.Equal(args[:2], []string{"-f", "-r"}):
		if !exists {
			h.groups[name] = nil
		}
	case tool == "dseditgroup" && slices.Equal(args[:2], []string{"-o", "create"}) && !exists:
		h.groups[name] = nil
	case (tool == "getent" && args[0] == "group" || tool == "dseditgroup" && args[1] == "read") && exists:
	case (tool == "groupdel" || tool == "dseditgroup" && args[1] == "delete") && exists:
		delete(h.groups, name)
	case tool == "usermod" && slices.Equal(args[:2], []string{"-a", "-G"}) && h.hasGroup(args[2]):
		h.groups[args[2]] = append(h.groups[args[2]], args[3])
	case tool == "dseditgroup" && args[1] == "edit" && args[2] == "-a" && exists:
		h.groups[name] = append(h.groups[name], args[3])
	default:
		return "", fmt.Errorf("%s %v: refused", tool, args)
	}
	return "", nil
}

func (h *fakeHost) hasGroup(name string) bool { _, ok := h.groups[name]; return ok }

// installer is an Installer on h for sys, with a binary to copy and a
// node that is ready.
func (h *fakeHost) installer(sys System) (Installer, *bytes.Buffer) {
	exe := filepath.Join(h.root, "home", "thinkpol")
	// The host has its manager's directory, and somewhere to copy from.
	for _, dir := range []string{filepath.Dir(exe), filepath.Join(h.root, filepath.Dir(sys.DefinitionPath()))} {
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
		RuntimeDirs: []string{"/run/thinkpol", "/run/thinkpol-api"}, Out: &out,
	}, &out
}

func (h *fakeHost) file(p string) ([]byte, os.FileMode, bool) {
	fi, err := os.Lstat(filepath.Join(h.root, p))
	if err != nil {
		return nil, 0, false
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
	if !bytes.Contains(unit, []byte("Environment=THINKPOL_CONNECT=false\n")) {
		t.Fatalf("connect-on-boot isn't off by default:\n%s", unit)
	}
	bin, mode, ok := h.file(BinaryPath)
	if !ok || mode.Perm() != 0o755 || string(bin) != "the thinkpol binary" {
		t.Fatalf("the binary: %v %v %q", ok, mode, bin)
	}
	if !h.enabled[UnitName] || !h.active[UnitName] || !slices.Equal(h.groups[Group], []string{"alice"}) {
		t.Fatalf("enabled %v, active %v, group %v", h.enabled, h.active, h.groups)
	}
	if c, err := in.ConnectOnBoot(); err != nil || c {
		t.Fatalf("connect-on-boot: %v %v", c, err)
	}

	// The toggle rewrites the unit for the next boot, without a restart.
	reloads := h.reloads
	if err := in.SetConnectOnBoot(ctx, true); err != nil {
		t.Fatal(err)
	}
	if c, err := in.ConnectOnBoot(); err != nil || !c || h.starts[UnitName] != 1 || h.reloads != reloads+1 {
		t.Fatalf("connect-on-boot %v %v, %d starts, %d reloads", c, err, h.starts[UnitName], h.reloads)
	}
	// Installed again (a new binary): restarted, the toggle kept unless
	// the install sets it.
	if err := in.Install(ctx, Options{}); err != nil {
		t.Fatal(err)
	}
	if c, _ := in.ConnectOnBoot(); !c || h.starts[UnitName] != 2 {
		t.Fatalf("after a reinstall: connect-on-boot %v, %d starts", c, h.starts[UnitName])
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
			for _, f := range []string{"/run/thinkpol/agent.lock", "/run/thinkpol/connect", "/run/thinkpol/netcfg/overlay.lock",
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
				"/run/thinkpol/connect", "/run/thinkpol/netcfg/overlay.lock"} {
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
			if h.hasGroup(Group) || h.loaded || h.active[UnitName] || h.enabled[UnitName] {
				t.Fatalf("group %v, launchd loaded %v, systemd active %v enabled %v", h.groups, h.loaded, h.active, h.enabled)
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

func TestInstallUnderLaunchd(t *testing.T) {
	h := newFakeHost(t)
	in, _ := h.installer(Launchd{})
	ctx := context.Background()
	// A daemon just booted out may still be going: bootstrap is retried.
	h.failNext["launchctl bootstrap"] = 2
	if err := in.Install(ctx, Options{User: "alice"}); err != nil {
		t.Fatal(err)
	}
	plist, mode, ok := h.file(PlistPath)
	if !ok || mode.Perm() != 0o644 || !bytes.Equal(plist, LaunchdPlist(Definition{Binary: BinaryPath})) {
		t.Fatalf("the plist (%v, %v):\n%s", ok, mode, plist)
	}
	if !h.loaded || !bytes.Equal(h.loadedFrom, plist) || !slices.Equal(h.groups[Group], []string{"alice"}) {
		t.Fatalf("loaded %v, group %v", h.loaded, h.groups)
	}
	// The toggle is for the next boot: the loaded daemon keeps its plist.
	if err := in.SetConnectOnBoot(ctx, true); err != nil {
		t.Fatal(err)
	}
	if c, err := in.ConnectOnBoot(); err != nil || !c || !bytes.Equal(h.loadedFrom, plist) {
		t.Fatalf("connect-on-boot %v %v", c, err)
	}
	// Installed again: booted out and in, on the new plist.
	if err := in.Install(ctx, Options{}); err != nil {
		t.Fatal(err)
	}
	if !h.loaded || !bytes.Contains(h.loadedFrom, []byte("<string>true</string>")) {
		t.Fatalf("reinstalled: loaded %v from\n%s", h.loaded, h.loadedFrom)
	}
	// A disabled daemon is enabled again.
	h.disabled = true
	if err := in.Install(ctx, Options{}); err != nil || !h.loaded {
		t.Fatalf("a disabled daemon: %v, loaded %v", err, h.loaded)
	}
}

func TestInstallRefusesBeforeChangingAnything(t *testing.T) {
	t.Run("a node that can't run", func(t *testing.T) {
		h := newFakeHost(t)
		in, _ := h.installer(Systemd{})
		in.Ready = func() error { return errors.New("no node.key") }
		if err := in.Install(context.Background(), Options{User: "alice"}); err == nil || !strings.Contains(err.Error(), "no node.key") {
			t.Fatalf("got %v", err)
		}
		if _, _, ok := h.file(BinaryPath); ok || h.hasGroup(Group) {
			t.Fatal("installed something")
		}
	})
	t.Run("a binary directory others can write to", func(t *testing.T) {
		h := newFakeHost(t)
		in, _ := h.installer(Systemd{})
		dir := filepath.Join(h.root, filepath.Dir(BinaryPath))
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if err := in.Install(context.Background(), Options{}); err == nil {
			t.Fatal("installed into a directory others can write to")
		}
		if _, _, ok := h.file(BinaryPath); ok {
			t.Fatal("the binary was copied")
		}
	})
}

func TestADefinitionChangedByHandIsNotInstalled(t *testing.T) {
	h := newFakeHost(t)
	in, _ := h.installer(Systemd{})
	if err := in.Install(context.Background(), Options{}); err != nil {
		t.Fatal(err)
	}
	unit, _, _ := h.file(UnitPath)
	edited := bytes.Replace(unit, []byte("up\n"), []byte("up -log-level debug\n"), 1)
	if err := os.WriteFile(filepath.Join(h.root, UnitPath), edited, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := in.SetConnectOnBoot(context.Background(), true); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("got %v", err)
	}
	if now, _, _ := h.file(UnitPath); !bytes.Equal(now, edited) {
		t.Fatal("the edited unit was rewritten")
	}
}
