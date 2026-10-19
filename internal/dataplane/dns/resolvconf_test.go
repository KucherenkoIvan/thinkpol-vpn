package dns

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Unprotected sorts a Problem: an untagged error is unprotected (a
// System that reports a problem it doesn't name fails closed), only nil
// and ErrUpstreamsStale are not.
func TestUnprotectedSortsProblems(t *testing.T) {
	if Unprotected(nil) {
		t.Error("nil is unprotected")
	}
	if !Unprotected(ErrUnprotected) || !Unprotected(fmt.Errorf("%w: rewrite failed", ErrUnprotected)) {
		t.Error("an ErrUnprotected problem is not unprotected")
	}
	if Unprotected(fmt.Errorf("%w: read failed", ErrUpstreamsStale)) {
		t.Error("stale upstreams are unprotected")
	}
	if !Unprotected(errors.New("the store is unreadable")) {
		t.Error("an untagged problem reads as protected")
	}
	if !Unprotected(fmt.Errorf("dns: %w; %w", nil, nil)) {
		t.Error("a problem wrapping only nils reads as protected")
	}
	if !Unprotected(taggedUnprotected{fmt.Errorf("%w: read failed", ErrUpstreamsStale)}) {
		t.Error("a wrapper that is ErrUnprotected around a stale problem reads as protected")
	}
	stale := fmt.Errorf("%w: read failed", ErrUpstreamsStale)
	if !Unprotected(errors.Join(errors.New("the store is unreadable"), stale)) {
		t.Error("an untagged problem joined with a stale one reads as protected")
	}
	if !Unprotected(errors.Join(stale, fmt.Errorf("%w: rewrite failed", ErrUnprotected))) {
		t.Error("an unprotected problem joined with a stale one reads as protected")
	}
	if !Unprotected(fmt.Errorf("checking: %w", errors.Join(stale, errors.New("the store is unreadable")))) {
		t.Error("a wrapped join with an untagged part reads as protected")
	}
	if Unprotected(errors.Join(stale, fmt.Errorf("again: %w", ErrUpstreamsStale))) {
		t.Error("two stale problems are unprotected")
	}
	if Unprotected(errors.Join(nil, nil)) {
		t.Error("a join of nothing is unprotected")
	}
}

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
	r, err := setResolvConf(path, "", testSystem)
	if err != nil {
		t.Fatal(err)
	}
	got := readString(t, path)
	if servers := nameservers([]byte(got)); !slices.Equal(servers, testSystem.Servers) {
		t.Errorf("nameservers %v in\n%s", servers, got)
	}
	for _, want := range []string{"\nsearch home.internal\n", "\noptions timeout:1 attempts:2\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("no %q in\n%s", want, got)
		}
	}
	// The OS's own search domains are out while the node runs: a failed
	// name retried under one would go wherever the rules send that domain.
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(line, "search") && strings.Contains(line, "lan") {
			t.Errorf("the original search domain stays: %q", line)
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
	r, err := setResolvConf(path, "", next)
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
	r, err := setResolvConf(path, "", testSystem)
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
	r, err := setResolvConf(path, "", testSystem)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	upstreams := make(chan []netip.Addr, 1)
	r.mu.Lock()
	r.cfg.Upstreams = func(a []netip.Addr) { upstreams <- a }
	r.mu.Unlock()
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
	select {
	case got := <-upstreams:
		if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.99")}) {
			t.Errorf("told the OS's resolvers are %v", got)
		}
	case <-time.After(time.Second):
		t.Error("not told the OS's resolvers changed")
	}
	if err := r.Problem(); err != nil {
		t.Errorf("problem %v", err)
	}
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != renewed {
		t.Errorf("restored\n%s\nwant the renewed one", got)
	}
}

func TestARewrittenResolvConfFiltersStubUpstreams(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "resolv.conf")
	uplink := filepath.Join(dir, "uplink.conf")
	if err := os.WriteFile(path, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := setResolvConf(path, uplink, testSystem)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	upstreams := make(chan []netip.Addr, 2)
	var lastUpstreams []netip.Addr
	r.mu.Lock()
	r.cfg.Upstreams = func(a []netip.Addr) {
		lastUpstreams = a
		upstreams <- a
	}
	r.mu.Unlock()

	mixed := "nameserver 127.0.0.53\nnameserver 192.0.2.88\n"
	if err := os.WriteFile(path, []byte(mixed), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * resolvConfCheck)
	for !slices.Equal(nameservers([]byte(readString(t, path))), testSystem.Servers) {
		if time.Now().After(deadline) {
			t.Fatalf("not taken back:\n%s", readString(t, path))
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case got := <-upstreams:
		want := []netip.Addr{netip.MustParseAddr("192.0.2.88")}
		if !slices.Equal(got, want) {
			t.Errorf("mixed stub and real: upstreams %v, want %v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("mixed stub and real: not told upstreams changed")
	}

	if err := os.WriteFile(uplink, []byte("nameserver 198.51.100.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stubOnly := "nameserver 127.0.0.53\n"
	if err := os.WriteFile(path, []byte(stubOnly), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * resolvConfCheck)
	for !slices.Equal(nameservers([]byte(readString(t, path))), testSystem.Servers) {
		if time.Now().After(deadline) {
			t.Fatalf("stub-only rewrite not taken back:\n%s", readString(t, path))
		}
		time.Sleep(100 * time.Millisecond)
	}
	select {
	case got := <-upstreams:
		want := []netip.Addr{netip.MustParseAddr("198.51.100.53")}
		if !slices.Equal(got, want) {
			t.Errorf("stub-only with uplink: upstreams %v, want %v", got, want)
		}
	case <-time.After(time.Second):
		t.Fatal("stub-only with uplink: not told upstreams changed")
	}

	if err := os.Remove(uplink); err != nil {
		t.Fatal(err)
	}
	stubOnlyOther := "nameserver 127.0.0.54\noptions edns0\n"
	if err := os.WriteFile(path, []byte(stubOnlyOther), 0o644); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(3 * resolvConfCheck)
	for !slices.Equal(nameservers([]byte(readString(t, path))), testSystem.Servers) {
		if time.Now().After(deadline) {
			t.Fatalf("stub-only without uplink not taken back:\n%s", readString(t, path))
		}
		time.Sleep(100 * time.Millisecond)
	}
	wantKept := []netip.Addr{netip.MustParseAddr("198.51.100.53")}
	select {
	case got := <-upstreams:
		t.Errorf("stub-only without uplink: upstreams %v, want previous kept without callback", got)
	case <-time.After(300 * time.Millisecond):
	}
	if !slices.Equal(lastUpstreams, wantKept) {
		t.Errorf("stub-only without uplink: upstreams %v, want previous %v kept", lastUpstreams, wantKept)
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

// A new configuration goes over the old one; the original stays.
func TestResolvConfUpdatesInPlace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	r, err := setResolvConf(path, "", testSystem)
	if err != nil {
		t.Fatal(err)
	}
	next := SystemConfig{Servers: testSystem.Servers[:1], Search: []string{"other.internal"}}
	if err := r.Update(next); err != nil {
		t.Fatal(err)
	}
	got := readString(t, path)
	if !slices.Equal(nameservers([]byte(got)), next.Servers) || !strings.Contains(got, "\nsearch other.internal\n") {
		t.Errorf("after Update:\n%s", got)
	}
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != isp {
		t.Errorf("restored\n%s", got)
	}
}

// What a crash left is put back when the node starts, whatever it does
// next; anything else is left alone.
func TestALeftoverIsRestoredAtStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, render(testSystem, []byte(isp), ""), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := restoreResolvConf(path); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != isp {
		t.Errorf("restored\n%s", got)
	}
	if err := restoreResolvConf(path); err != nil || readString(t, path) != isp {
		t.Errorf("a file the node doesn't manage changed: %v", err)
	}
}

// taggedUnprotected is ErrUnprotected itself, whatever it wraps.
type taggedUnprotected struct{ inner error }

func (e taggedUnprotected) Error() string        { return "unprotected: " + e.inner.Error() }
func (e taggedUnprotected) Unwrap() error        { return e.inner }
func (e taggedUnprotected) Is(target error) bool { return target == ErrUnprotected }
