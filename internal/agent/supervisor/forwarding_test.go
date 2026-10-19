package supervisor

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeKernelSys is procSysFS with the kernel's side effects of writing the
// forwarding switches, and an onWrite hook for tests that refuse a write.
type fakeKernelSys struct {
	procSysFS
	onWrite func(key, value string) error
}

func (f *fakeKernelSys) Write(key, value string) error {
	if f.onWrite != nil {
		if err := f.onWrite(key, value); err != nil {
			return err
		}
	}
	if err := f.procSysFS.Write(key, value); err != nil {
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
	sys := &fakeKernelSys{procSysFS: procSysFS{root: dir}}
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
	sys.onWrite = func(key, value string) error {
		if key == forwardingKeys[1] && value == "0" {
			return errors.New("refused")
		}
		return nil
	}
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
	sys.onWrite = nil

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

func TestMaxFlowsDefaultsToAQuarterOfConntrack(t *testing.T) {
	sys, _ := fakeProcSys(t)
	if got := maxFlows(0, sys); got != 262144/4 {
		t.Fatalf("default %d", got)
	}
	if maxFlows(-1, sys) != 0 || maxFlows(10, sys) != 10 {
		t.Fatal("explicit caps not kept")
	}
}
