package dns

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

var testSystem = SystemConfig{
	Servers: []netip.Addr{netip.MustParseAddr("100.64.0.2"), netip.MustParseAddr("fd12:3456:789a::2")},
	Search:  []string{"home.internal"},
}

const isp = "# from DHCP\nnameserver 192.0.2.53\nnameserver 2001:db8::53\nsearch lan\noptions timeout:1 attempts:2\n"

func readString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestResolvConfIsReplacedAndRestored(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := setResolvConf(path, testSystem)
	if err != nil {
		t.Fatal(err)
	}
	got := readString(t, path)
	if servers := nameservers([]byte(got)); !slices.Equal(servers, testSystem.Servers) {
		t.Errorf("nameservers %v in\n%s", servers, got)
	}
	for _, want := range []string{"search home.internal lan\n", "options timeout:1 attempts:2\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	// What the OS used before stays readable while the node runs.
	if orig, err := originalResolvConf(path); err != nil || string(orig) != isp {
		t.Errorf("original %q, %v", orig, err)
	}
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != isp {
		t.Errorf("restored\n%s\nwant\n%s", got, isp)
	}
	if err := r.Restore(); err != nil {
		t.Errorf("second Restore: %v", err)
	}
}

// After a crash the managed file is still there; the next run keeps the
// original it holds, and restoring puts that back.
func TestALeftoverResolvConfKeepsItsOriginal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, render(testSystem, []byte(isp), ""), 0o644); err != nil {
		t.Fatal(err)
	}
	next := testSystem
	next.Servers = next.Servers[:1]
	r, err := setResolvConf(path, next)
	if err != nil {
		t.Fatal(err)
	}
	if servers := nameservers([]byte(readString(t, path))); !slices.Equal(servers, next.Servers) {
		t.Errorf("nameservers %v", servers)
	}
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != isp {
		t.Errorf("restored\n%s", got)
	}
}

func TestASymlinkedResolvConfComesBackAsTheLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "managed-elsewhere.conf")
	if err := os.WriteFile(target, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "resolv.conf")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	r, err := setResolvConf(path, testSystem)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(path); err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("while running: %v, %v", fi.Mode(), err)
	}
	if got := readString(t, target); got != isp {
		t.Error("the link's target was changed")
	}
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if link, err := os.Readlink(path); err != nil || link != target {
		t.Errorf("restored link %q, %v", link, err)
	}
}

// Another program rewriting resolv.conf while the node runs (a DHCP
// client) would send names around the resolver: the file is taken back,
// with the new content as the original.
func TestAResolvConfRewrittenMeanwhileIsTakenBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := setResolvConf(path, testSystem)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	renewed := "nameserver 192.0.2.99\n"
	if err := os.WriteFile(path, []byte(renewed), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * resolvConfCheck)
	for !slices.Equal(nameservers([]byte(readString(t, path))), testSystem.Servers) {
		if time.Now().After(deadline) {
			t.Fatalf("not taken back:\n%s", readString(t, path))
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != renewed {
		t.Errorf("restored\n%s\nwant the renewed one", got)
	}
}

func TestSystemUpstreams(t *testing.T) {
	dir := t.TempDir()
	etc, uplink := filepath.Join(dir, "resolv.conf"), filepath.Join(dir, "uplink.conf")
	own := testSystem.Servers
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	check := func(what string, want ...string) {
		t.Helper()
		got, err := upstreamsFrom(etc, uplink, own)
		if err != nil {
			t.Fatal(err)
		}
		var gs []string
		for _, a := range got {
			gs = append(gs, a.String())
		}
		if !slices.Equal(gs, want) {
			t.Errorf("%s: %v, want %v", what, gs, want)
		}
	}
	write(etc, isp)
	check("a plain resolv.conf", "192.0.2.53", "2001:db8::53")
	write(etc, string(render(testSystem, []byte(isp), "")))
	check("while the node manages it", "192.0.2.53", "2001:db8::53")
	write(etc, "nameserver 127.0.0.53\noptions edns0 trust-ad\n")
	write(uplink, "nameserver 198.51.100.53\nnameserver 100.64.0.2\n")
	check("through systemd-resolved, without the node's own", "198.51.100.53")
}
