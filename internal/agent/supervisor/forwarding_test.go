package supervisor

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// hookSysctls is the real /proc/sys whose writes a test can watch or
// refuse along the way. The hook is armed and disarmed atomically: the
// fake is set at New (Options.sysctls) and never written afterwards.
type hookSysctls struct {
	procSysFS
	hook atomic.Pointer[func(key, value string) error]
}

// arm runs hook before every write; disarm when the test is done with it.
func (h *hookSysctls) arm(hook func(key, value string) error) { h.hook.Store(&hook) }

func (h *hookSysctls) disarm() { h.hook.Store(nil) }

func (h *hookSysctls) Write(key, value string) error {
	if f := h.hook.Load(); f != nil {
		if err := (*f)(key, value); err != nil {
			return err
		}
	}
	return h.procSysFS.Write(key, value)
}

// fakeKernelSys is hookSysctls with the kernel's side effects of writing
// the forwarding switches. A Glob for refuseGlob fails; it is set before
// the sysctls are used.
type fakeKernelSys struct {
	hookSysctls
	refuseGlob string
}

func (f *fakeKernelSys) Glob(pattern string) ([]string, error) {
	if pattern == f.refuseGlob {
		return nil, errors.New("refused")
	}
	return f.hookSysctls.Glob(pattern)
}

func (f *fakeKernelSys) Write(key, value string) error {
	if err := f.hookSysctls.Write(key, value); err != nil {
		return err
	}
	// The kernel: IPv4's switch resets accept_redirects and every
	// interface's forwarding; IPv6's sets every interface's forwarding.
	switch key {
	case "net/ipv4/ip_forward":
		f.set("net/ipv4/conf/*/forwarding", value)
		redirects := "1"
		if value == "1" {
			redirects = "0"
		}
		f.set("net/ipv4/conf/all/accept_redirects", redirects)
	case "net/ipv6/conf/all/forwarding":
		f.set("net/ipv6/conf/*/forwarding", value)
	}
	return nil
}

func (f *fakeKernelSys) set(glob, value string) {
	matches, _ := filepath.Glob(filepath.Join(f.root, glob))
	for _, m := range matches {
		_ = os.WriteFile(m, []byte(value), 0o644)
	}
}

// fakeProcSys is a /proc/sys holding the forwarding sysctls of a node with
// an RA-configured uplink eth0 and a space's veth end, whose forwarding
// switches have the kernel's side effects. It returns the sysctls and a
// getter for the tests' assertions.
func fakeProcSys(t *testing.T) (*fakeKernelSys, func(key string) string) {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"net/ipv4/ip_forward":            "0",
		"net/netfilter/nf_conntrack_max": "262144",
	}
	for _, dev := range []string{"all", "default", "eth0"} {
		files["net/ipv4/conf/"+dev+"/accept_redirects"] = "0" // hardened by the admin
		files["net/ipv4/conf/"+dev+"/forwarding"] = "0"
	}
	for _, dev := range []string{"all", "default", "eth0", "tp-space0"} {
		files["net/ipv6/conf/"+dev+"/forwarding"] = "0"
		files["net/ipv6/conf/"+dev+"/accept_ra"] = "1"
	}
	files["net/ipv6/conf/eth1/forwarding"] = "1" // forwards on its own
	files["net/ipv6/conf/eth1/accept_ra"] = "0"
	for k, v := range files {
		path := filepath.Join(dir, k)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(v+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	sys := &fakeKernelSys{hookSysctls: hookSysctls{procSysFS: procSysFS{root: dir}}}
	return sys, func(key string) string {
		v, err := sys.Read(key)
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}

func TestForwardingIsTurnedOnRecordedAndPutBack(t *testing.T) {
	sys, get := fakeProcSys(t)
	run := t.TempDir()
	f := rootForwarding{sys: sys}
	if err := f.load(run); err != nil {
		t.Fatal(err)
	}
	if err := f.ensure([2]bool{true, true}); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"net/ipv4/ip_forward":                "1",
		"net/ipv6/conf/all/forwarding":       "1",
		"net/ipv6/conf/eth0/accept_ra":       "2", // before IPv6 forwarding: keeps its default route
		"net/ipv6/conf/default/accept_ra":    "2",
		"net/ipv6/conf/tp-space0/accept_ra":  "1", // a space's veth end: never the uplink
		"net/ipv4/conf/all/accept_redirects": "0",
		"net/ipv4/conf/eth0/forwarding":      "1",
	} {
		if got := get(key); got != want {
			t.Errorf("%s = %s, want %s", key, got, want)
		}
	}
	if f.owned() != [2]bool{true, true} {
		t.Fatalf("owned %v", f.owned())
	}

	// A successor adopts the record: the switches still hold what was
	// written.
	next := rootForwarding{sys: sys}
	if err := next.load(run); err != nil {
		t.Fatal(err)
	}
	if next.owned() != [2]bool{true, true} {
		t.Fatalf("successor owns %v", next.owned())
	}
	// Someone set eth0's accept_ra meanwhile: it isn't put back.
	if err := sys.procSysFS.Write("net/ipv6/conf/eth0/accept_ra", "0"); err != nil {
		t.Fatal(err)
	}
	if err := next.restore(); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{
		"net/ipv4/ip_forward":                "0",
		"net/ipv6/conf/all/forwarding":       "0",
		"net/ipv6/conf/eth1/forwarding":      "1", // reset by the switch, put back
		"net/ipv4/conf/all/accept_redirects": "0", // the same
		"net/ipv6/conf/eth0/accept_ra":       "0", // changed by someone else: left
		"net/ipv6/conf/default/accept_ra":    "1",
	} {
		if got := get(key); got != want {
			t.Errorf("after restore: %s = %s, want %s", key, got, want)
		}
	}
	if _, err := os.Stat(filepath.Join(run, forwardingFile)); !os.IsNotExist(err) {
		t.Errorf("the record outlived the restore: %v", err)
	}
}

// Forwarding that was on already is the node's: neither owned nor turned
// off; and the supervisor's is turned off once no space needs it.
func TestForwardingOnAlreadyIsLeftAlone(t *testing.T) {
	sys, get := fakeProcSys(t)
	if err := sys.Write("net/ipv4/ip_forward", "1"); err != nil {
		t.Fatal(err)
	}
	f := rootForwarding{sys: sys}
	if err := f.load(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	if w := f.willOwn([2]bool{true, true}); w != [2]bool{false, true} {
		t.Fatalf("would own %v", w)
	}
	if err := f.ensure([2]bool{true, true}); err != nil {
		t.Fatal(err)
	}
	if f.owned() != [2]bool{false, true} {
		t.Fatalf("owned %v", f.owned())
	}
	if err := f.ensure([2]bool{true, false}); err != nil {
		t.Fatal(err)
	}
	if f.owned() != [2]bool{} || get("net/ipv6/conf/all/forwarding") != "0" || get("net/ipv4/ip_forward") != "1" {
		t.Fatalf("owned %v, forwarding %s/%s", f.owned(), get("net/ipv4/ip_forward"), get("net/ipv6/conf/all/forwarding"))
	}
	if err := f.restore(); err != nil || get("net/ipv4/ip_forward") != "1" {
		t.Fatalf("restore turned the node's own forwarding off: %v", err)
	}
}

// A record whose switch someone else changed since is not adopted.
func TestForwardingRecordOfAChangedSwitchIsDropped(t *testing.T) {
	sys, get := fakeProcSys(t)
	run := t.TempDir()
	f := rootForwarding{sys: sys}
	if err := f.load(run); err != nil {
		t.Fatal(err)
	}
	if err := f.ensure([2]bool{true, false}); err != nil {
		t.Fatal(err)
	}
	// Someone else's write, without the supervisor's switch's side effects.
	if err := sys.procSysFS.Write("net/ipv4/ip_forward", "0"); err != nil {
		t.Fatal(err)
	}
	next := rootForwarding{sys: sys}
	if err := next.load(run); err != nil {
		t.Fatal(err)
	}
	if next.owned() != [2]bool{} {
		t.Fatalf("adopted a switch someone else turned off: %v", next.owned())
	}
	if err := next.restore(); err != nil || get("net/ipv4/ip_forward") != "0" {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(run, forwardingFile))
	if strings.TrimSpace(string(b)) != "" {
		t.Fatalf("record left: %s", b)
	}
}

// Forwarding that can't be turned off stays the supervisor's, recorded,
// with IPv6's accept_ra still 2: a successor adopts it and turns it off.
func TestForwardingThatCannotBeTurnedOffStaysRecorded(t *testing.T) {
	sys, get := fakeProcSys(t)
	run := t.TempDir()
	f := rootForwarding{sys: sys}
	if err := f.load(run); err != nil {
		t.Fatal(err)
	}
	if err := f.ensure([2]bool{true, true}); err != nil {
		t.Fatal(err)
	}
	sys.arm(func(key, value string) error {
		if key == forwardingKeys[1] && value == "0" {
			return errors.New("refused")
		}
		return nil
	})
	if err := f.restore(); err == nil {
		t.Fatal("restore returned nil with IPv6 forwarding still on")
	}
	if f.owned() != [2]bool{false, true} {
		t.Fatalf("owned %v after a restore that turned IPv4 off only", f.owned())
	}
	for key, want := range map[string]string{
		"net/ipv4/ip_forward":          "0",
		"net/ipv6/conf/all/forwarding": "1",
		"net/ipv6/conf/eth0/accept_ra": "2",
	} {
		if got := get(key); got != want {
			t.Errorf("after the failed restore: %s = %s, want %s", key, got, want)
		}
	}
	sys.disarm()

	next := rootForwarding{sys: sys}
	if err := next.load(run); err != nil {
		t.Fatal(err)
	}
	if next.owned() != [2]bool{false, true} {
		t.Fatalf("successor owns %v", next.owned())
	}
	if err := next.restore(); err != nil {
		t.Fatal(err)
	}
	if get("net/ipv6/conf/all/forwarding") != "0" || get("net/ipv6/conf/eth0/accept_ra") != "1" {
		t.Fatalf("successor's restore: forwarding %s, accept_ra %s", get("net/ipv6/conf/all/forwarding"), get("net/ipv6/conf/eth0/accept_ra"))
	}
	if _, err := os.Stat(filepath.Join(run, forwardingFile)); !os.IsNotExist(err) {
		t.Errorf("the record outlived the restore: %v", err)
	}
}

// An IPv6 forwarding attempt that fails before its switch is flipped puts
// back the accept_ra values it already wrote and touches nothing else: a
// switch someone else turned on meanwhile stays on, and isn't the
// supervisor's. Nothing is left changed, or recorded.
func TestForwardingThatFailsToTurnOnLeavesAcceptRAAsItWas(t *testing.T) {
	eth0RA := "net/ipv6/conf/eth0/accept_ra"
	for _, tc := range []struct {
		name string
		// hook runs before every write, with the fake's own setter.
		hook       func(sys *fakeKernelSys, key, value string) error
		refuseGlob string
		wantSwitch string
		wantEth0RA string // "" for 1
	}{
		{name: "an accept_ra write refused", hook: func(_ *fakeKernelSys, key, value string) error {
			if key == eth0RA && value == "2" {
				return errors.New("refused")
			}
			return nil
		}, wantSwitch: "0"},
		{name: "the interfaces unlistable", refuseGlob: "net/ipv6/conf/*", wantSwitch: "0"},
		{name: "the side sysctls unreadable", refuseGlob: "net/ipv6/conf/*/forwarding", wantSwitch: "0"},
		{name: "the switch refused", hook: func(_ *fakeKernelSys, key, value string) error {
			if key == forwardingKeys[1] && value == "1" {
				return errors.New("refused")
			}
			return nil
		}, wantSwitch: "0"},
		{name: "someone else's forwarding turned on meanwhile", hook: func(sys *fakeKernelSys, key, value string) error {
			if key == eth0RA && value == "2" {
				sys.set("net/ipv6/conf/*/forwarding", "1") // as a container runtime would
				return errors.New("refused")
			}
			return nil
		}, wantSwitch: "1"},
		{name: "an accept_ra changed by someone else meanwhile", hook: func(sys *fakeKernelSys, key, value string) error {
			if key == forwardingKeys[1] && value == "1" {
				if err := sys.procSysFS.Write(eth0RA, "0"); err != nil {
					return err
				}
				return errors.New("refused")
			}
			return nil
		}, wantSwitch: "0", wantEth0RA: "0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sys, get := fakeProcSys(t)
			sys.refuseGlob = tc.refuseGlob
			run := t.TempDir()
			f := rootForwarding{sys: sys}
			if err := f.load(run); err != nil {
				t.Fatal(err)
			}
			if tc.hook != nil {
				sys.arm(func(key, value string) error { return tc.hook(sys, key, value) })
			}
			if err := f.ensure([2]bool{false, true}); err == nil {
				t.Fatal("ensure returned nil with IPv6 forwarding refused")
			}
			sys.disarm()
			sys.refuseGlob = ""
			if f.owned() != [2]bool{} {
				t.Errorf("owned = %v after the failed attempt, want none", f.owned())
			}
			wantEth0RA := tc.wantEth0RA
			if wantEth0RA == "" {
				wantEth0RA = "1"
			}
			for key, want := range map[string]string{"net/ipv6/conf/default/accept_ra": "1", eth0RA: wantEth0RA} {
				if got := get(key); got != want {
					t.Errorf("%s = %s after the failed attempt, want %s", key, got, want)
				}
			}
			if got := get(forwardingKeys[1]); got != tc.wantSwitch {
				t.Errorf("IPv6 forwarding = %s after the failed attempt, want %s", got, tc.wantSwitch)
			}
			if _, err := os.Stat(filepath.Join(run, forwardingFile)); !os.IsNotExist(err) {
				t.Errorf("a record of the failed attempt: %v", err)
			}
		})
	}
}

func TestMaxFlowsDefaultsToAQuarterOfConntrack(t *testing.T) {
	sys, _ := fakeProcSys(t)
	if got := maxFlows(0, sys); got != 262144/4 {
		t.Fatalf("default %d", got)
	}
	if maxFlows(-1, sys) != 0 || maxFlows(10, sys) != 10 {
		t.Fatal("explicit caps not kept")
	}
}

// crashSys copies the sysctls and the run dir before and after every write:
// what a supervisor killed at that point leaves behind.
type crashSys struct {
	*fakeKernelSys
	t       *testing.T
	run     string
	crashes []crashPoint
}

type crashPoint struct {
	name     string
	sys, run string
}

func (c *crashSys) Write(key, value string) error {
	c.snapshot("before writing " + key + "=" + value)
	err := c.fakeKernelSys.Write(key, value)
	c.snapshot("after writing " + key + "=" + value)
	return err
}

func (c *crashSys) snapshot(name string) {
	c.t.Helper()
	p := crashPoint{name: name, sys: c.t.TempDir(), run: c.t.TempDir()}
	for src, dst := range map[string]string{c.root: p.sys, c.run: p.run} {
		if err := os.CopyFS(dst, os.DirFS(src)); err != nil && !errors.Is(err, os.ErrExist) {
			c.t.Fatal(err)
		}
	}
	c.crashes = append(c.crashes, p)
}

// afterWriteSys runs after, if set, once a write has gone through.
type afterWriteSys struct {
	*fakeKernelSys
	after func(key string)
}

func (a *afterWriteSys) Write(key, value string) error {
	err := a.fakeKernelSys.Write(key, value)
	if err == nil && a.after != nil {
		a.after(key)
	}
	return err
}

// sysctlTree is every sysctl under root, by key.
func sysctlTree(t *testing.T, root string) map[string]string {
	t.Helper()
	tree := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		key, _ := filepath.Rel(root, path)
		tree[key] = strings.TrimSpace(string(b))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return tree
}

// checkSuccessor starts a successor on what a dead supervisor left (the
// sysctls under sysRoot, the record in run): every forwarding switch it
// finds on that was off at first is its own (so its tables confine it),
// and once it restores, every sysctl is back to before (want).
func checkSuccessor(t *testing.T, sysRoot, run string, want map[string]string) {
	t.Helper()
	sys := &fakeKernelSys{hookSysctls: hookSysctls{procSysFS: procSysFS{root: sysRoot}}}
	next := rootForwarding{sys: sys}
	if err := next.load(run); err != nil {
		t.Fatalf("successor's load: %v", err)
	}
	for i, key := range forwardingKeys {
		if v, _ := sys.Read(key); v != want[key] && !next.owned()[i] {
			t.Errorf("%s = %s (was %s), owned by no one", key, v, want[key])
		}
	}
	if err := next.restore(); err != nil {
		t.Fatalf("successor's restore: %v", err)
	}
	got := sysctlTree(t, sysRoot)
	for key, v := range want {
		if got[key] != v {
			t.Errorf("after the successor's restore: %s = %s, want %s", key, got[key], v)
		}
	}
	if _, err := os.Stat(filepath.Join(run, forwardingFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the record outlived the successor's restore: %v", err)
	}
}

// A supervisor killed before or after any of its writes leaves a record
// its successor puts every value back from, or adopts the forwarding by
// (and confines it): never forwarding on that no one owns, nor accept_ra
// left at 2.
func TestForwardingKilledAtAnyWriteIsPutBackOrAdopted(t *testing.T) {
	fake, _ := fakeProcSys(t)
	want := sysctlTree(t, fake.root)
	run := t.TempDir()
	sys := &crashSys{fakeKernelSys: fake, t: t, run: run}
	f := rootForwarding{sys: sys}
	if err := f.load(run); err != nil {
		t.Fatal(err)
	}
	if err := f.ensure([2]bool{true, true}); err != nil {
		t.Fatal(err)
	}
	if len(sys.crashes) != 8 { // the IPv4 switch, default's and eth0's accept_ra, the IPv6 switch
		t.Fatalf("%d crash points, want 8", len(sys.crashes))
	}
	for _, p := range sys.crashes {
		t.Run(p.name, func(t *testing.T) { checkSuccessor(t, p.sys, p.run, want) })
	}
}

// A record that can't be saved fails the attempt, which puts back what it
// wrote; once the switch is flipped its record is saved already, and the
// family stays the supervisor's. A successor started then (the supervisor
// dying right after) puts everything back or adopts it.
func TestForwardingRecordThatCannotBeSavedFailsTheAttempt(t *testing.T) {
	for _, tc := range []struct {
		name string
		// failAfter makes saves fail once the write of this key returns;
		// "": from the start.
		failAfter string
		wantOwned [2]bool
	}{
		{name: "before the accept_ra writes", wantOwned: [2]bool{}},
		{name: "before the switch", failAfter: "net/ipv6/conf/eth0/accept_ra", wantOwned: [2]bool{}},
		{name: "after the switch", failAfter: forwardingKeys[1], wantOwned: [2]bool{false, true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fake, get := fakeProcSys(t)
			want := sysctlTree(t, fake.root)
			run := t.TempDir()
			sys := &afterWriteSys{fakeKernelSys: fake}
			f := rootForwarding{sys: sys}
			if err := f.load(run); err != nil {
				t.Fatal(err)
			}
			// A directory where the record's temporary file goes: every
			// save fails (removing the record doesn't), root or not.
			blocker := filepath.Join(run, forwardingFile+".new")
			block := func() {
				if err := os.Mkdir(blocker, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
					t.Error(err)
				}
			}
			if tc.failAfter == "" {
				block()
			} else {
				sys.after = func(key string) {
					if key == tc.failAfter {
						block()
					}
				}
			}
			if err := f.ensure([2]bool{false, true}); err == nil {
				t.Fatal("ensure returned nil with the record unsaved")
			}
			if f.owned() != tc.wantOwned {
				t.Errorf("owned = %v, want %v", f.owned(), tc.wantOwned)
			}
			if !tc.wantOwned[1] {
				for key, v := range want {
					if got := get(key); got != v {
						t.Errorf("after the failed attempt: %s = %s, want %s", key, got, v)
					}
				}
			}
			if err := os.Remove(blocker); err != nil {
				t.Fatal(err)
			}
			checkSuccessor(t, fake.root, run, want)
		})
	}
}

// A family the successor doesn't adopt, its switch turned off by someone
// else after the supervisor died, gets back the accept_ra values that
// still hold 2; one changed since is left.
func TestForwardingRecordOfASwitchTurnedOffPutsBackAcceptRA(t *testing.T) {
	sys, get := fakeProcSys(t)
	run := t.TempDir()
	f := rootForwarding{sys: sys}
	if err := f.load(run); err != nil {
		t.Fatal(err)
	}
	if err := f.ensure([2]bool{false, true}); err != nil {
		t.Fatal(err)
	}
	// The supervisor dies; an admin turns IPv6 forwarding off and sets
	// eth0's accept_ra.
	for key, v := range map[string]string{forwardingKeys[1]: "0", "net/ipv6/conf/eth0/accept_ra": "0"} {
		if err := sys.procSysFS.Write(key, v); err != nil {
			t.Fatal(err)
		}
	}
	next := rootForwarding{sys: sys}
	if err := next.load(run); err != nil {
		t.Fatal(err)
	}
	if next.owned() != [2]bool{} {
		t.Fatalf("adopted a switch someone else turned off: %v", next.owned())
	}
	for key, want := range map[string]string{
		"net/ipv6/conf/default/accept_ra": "1",
		"net/ipv6/conf/eth0/accept_ra":    "0", // changed by someone else: left
		forwardingKeys[1]:                 "0",
	} {
		if got := get(key); got != want {
			t.Errorf("after the successor's load: %s = %s, want %s", key, got, want)
		}
	}
	if _, err := os.Stat(filepath.Join(run, forwardingFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the record outlived the successor's load: %v", err)
	}
}

// A switch someone else turns on after the accept_ra writes and before the
// supervisor marks its own (killed in between) isn't adopted: the
// successor leaves it on and puts accept_ra back.
func TestForwardingSwitchTurnedOnBeforeItIsMarkedIsLeftAlone(t *testing.T) {
	fake, _ := fakeProcSys(t)
	run := t.TempDir()
	crash := &crashSys{fakeKernelSys: fake, t: t, run: run}
	sys := &afterWriteSys{fakeKernelSys: fake, after: func(key string) {
		if key == "net/ipv6/conf/eth0/accept_ra" { // the last accept_ra write
			fake.set("net/ipv6/conf/*/forwarding", "1") // as a container runtime would
			crash.snapshot("killed after the accept_ra writes")
		}
	}}
	f := rootForwarding{sys: sys}
	if err := f.load(run); err != nil {
		t.Fatal(err)
	}
	if err := f.ensure([2]bool{false, true}); err != nil {
		t.Fatal(err)
	}
	if len(crash.crashes) != 1 {
		t.Fatalf("%d snapshots, want 1", len(crash.crashes))
	}
	p := crash.crashes[0]
	want := sysctlTree(t, p.sys)
	for _, dev := range []string{"default", "eth0"} {
		if key := "net/ipv6/conf/" + dev + "/accept_ra"; want[key] != "2" {
			t.Fatalf("%s = %s at the snapshot, want 2", key, want[key])
		} else {
			want[key] = "1"
		}
	}
	next := rootForwarding{sys: &fakeKernelSys{hookSysctls: hookSysctls{procSysFS: procSysFS{root: p.sys}}}}
	if err := next.load(p.run); err != nil {
		t.Fatal(err)
	}
	if next.owned() != [2]bool{} {
		t.Fatalf("the successor adopted someone else's switch: owned = %v", next.owned())
	}
	if err := next.restore(); err != nil {
		t.Fatal(err)
	}
	for key, v := range sysctlTree(t, p.sys) {
		if v != want[key] {
			t.Errorf("after the successor: %s = %s, want %s", key, v, want[key])
		}
	}
}

// An accept_ra value that can't be put back stays in the record, under a
// switch that isn't the supervisor's, and the next start puts it back:
// whether the put-back failed in a failed attempt, in putting forwarding
// back, or in a successor's load.
func TestForwardingAcceptRAThatCannotBePutBackStaysRecorded(t *testing.T) {
	eth0RA := "net/ipv6/conf/eth0/accept_ra"
	refuse := func(refused ...string) func(key, value string) error {
		return func(key, value string) error {
			for i := 0; i < len(refused); i += 2 {
				if key == refused[i] && value == refused[i+1] {
					return errors.New("refused")
				}
			}
			return nil
		}
	}
	for _, tc := range []struct {
		name string
		// fail leaves eth0's accept_ra at 2, its put-back refused.
		fail func(t *testing.T, sys *fakeKernelSys, run string)
	}{
		{name: "in a failed attempt", fail: func(t *testing.T, sys *fakeKernelSys, run string) {
			f := rootForwarding{sys: sys}
			if err := f.load(run); err != nil {
				t.Fatal(err)
			}
			sys.arm(refuse(forwardingKeys[1], "1", eth0RA, "1"))
			defer sys.disarm()
			if err := f.ensure([2]bool{false, true}); err == nil {
				t.Fatal("ensure returned nil with IPv6 forwarding refused")
			}
			if f.owned() != [2]bool{} {
				t.Errorf("owned = %v after the failed attempt, want none", f.owned())
			}
		}},
		{name: "in putting forwarding back", fail: func(t *testing.T, sys *fakeKernelSys, run string) {
			f := rootForwarding{sys: sys}
			if err := f.load(run); err != nil {
				t.Fatal(err)
			}
			if err := f.ensure([2]bool{false, true}); err != nil {
				t.Fatal(err)
			}
			sys.arm(refuse(eth0RA, "1"))
			defer sys.disarm()
			if err := f.restore(); err == nil {
				t.Fatal("restore returned nil with accept_ra not put back")
			}
			if f.owned() != [2]bool{} {
				t.Errorf("owned = %v after the restore, want none", f.owned())
			}
		}},
		{name: "in a successor's load", fail: func(t *testing.T, sys *fakeKernelSys, run string) {
			f := rootForwarding{sys: sys}
			if err := f.load(run); err != nil {
				t.Fatal(err)
			}
			if err := f.ensure([2]bool{false, true}); err != nil {
				t.Fatal(err)
			}
			// The supervisor dies; an admin turns IPv6 forwarding off.
			if err := sys.procSysFS.Write(forwardingKeys[1], "0"); err != nil {
				t.Fatal(err)
			}
			sys.arm(refuse(eth0RA, "1"))
			defer sys.disarm()
			next := rootForwarding{sys: sys}
			if err := next.load(run); err == nil {
				t.Fatal("load returned nil with accept_ra not put back")
			}
			if next.owned() != [2]bool{} {
				t.Errorf("owned = %v after the load, want none", next.owned())
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sys, get := fakeProcSys(t)
			run := t.TempDir()
			tc.fail(t, sys, run)
			if got := get(eth0RA); got != "2" {
				t.Fatalf("%s = %s, want 2 (its put-back refused)", eth0RA, got)
			}
			// Someone else turns IPv6 forwarding on: the record's switch
			// isn't the supervisor's, so the next start leaves it on.
			sys.set("net/ipv6/conf/*/forwarding", "1")
			next := rootForwarding{sys: sys}
			if err := next.load(run); err != nil {
				t.Fatalf("the next start's load: %v", err)
			}
			if next.owned() != [2]bool{} {
				t.Errorf("the next start adopted someone else's switch: owned = %v", next.owned())
			}
			for key, want := range map[string]string{
				eth0RA:                            "1",
				"net/ipv6/conf/default/accept_ra": "1",
				forwardingKeys[1]:                 "1",
			} {
				if got := get(key); got != want {
					t.Errorf("after the next start's load: %s = %s, want %s", key, got, want)
				}
			}
			if _, err := os.Stat(filepath.Join(run, forwardingFile)); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("the record outlived the put-back: %v", err)
			}
		})
	}
}

// Forwarding turned on again after an attempt whose accept_ra put-back
// failed takes those values as its own, and puts them back with the rest.
func TestForwardingRetriedAfterAFailedPutBackOwnsItsAcceptRA(t *testing.T) {
	sys, get := fakeProcSys(t)
	want := sysctlTree(t, sys.root)
	run := t.TempDir()
	f := rootForwarding{sys: sys}
	if err := f.load(run); err != nil {
		t.Fatal(err)
	}
	eth0RA := "net/ipv6/conf/eth0/accept_ra"
	sys.arm(func(key, value string) error {
		if (key == forwardingKeys[1] || key == eth0RA) && value == "1" {
			return errors.New("refused")
		}
		return nil
	})
	if err := f.ensure([2]bool{false, true}); err == nil {
		t.Fatal("ensure returned nil with IPv6 forwarding refused")
	}
	sys.disarm()
	if got := get(eth0RA); got != "2" {
		t.Fatalf("%s = %s, want 2 (its put-back refused)", eth0RA, got)
	}
	if err := f.ensure([2]bool{false, true}); err != nil {
		t.Fatal(err)
	}
	if f.owned() != [2]bool{false, true} {
		t.Fatalf("owned = %v after the retry, want IPv6", f.owned())
	}
	if err := f.restore(); err != nil {
		t.Fatal(err)
	}
	for key, v := range sysctlTree(t, sys.root) {
		if v != want[key] {
			t.Errorf("after the restore: %s = %s, want %s", key, v, want[key])
		}
	}
	if _, err := os.Stat(filepath.Join(run, forwardingFile)); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the record outlived the restore: %v", err)
	}
}
