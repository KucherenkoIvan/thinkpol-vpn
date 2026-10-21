//go:build linux && !android

package dns

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// firstResolvedRead runs the read at setup as setResolved would, telling
// what it returned.
func firstResolvedRead(t *testing.T, r *resolved) {
	t.Helper()
	r.mu.Lock()
	tell := r.firstRead()
	r.mu.Unlock()
	if tell != nil {
		tell()
	}
}

// newTestResolved builds the configuration as setResolved does, without
// D-Bus (nil conn): the read and tell paths never touch it.
func newTestResolved(c SystemConfig, uplink bool, uplinkFile string) *resolved {
	return newResolved(nil, 0, c, uplink, uplinkFile)
}

// tickResolved runs one watch tick's read as the watcher would, telling
// what it returned.
func tickResolved(t *testing.T, r *resolved) {
	t.Helper()
	r.mu.Lock()
	tell := r.apply()
	r.mu.Unlock()
	if tell != nil {
		tell()
	}
}

// The caller's own read of the OS's resolvers failed (UpstreamsUnknown)
// and resolved is the OS's resolver: a missing uplink file is a failed
// read, stale until it appears; the first good read is told whether or
// not the servers changed, and an unchanged one after it tells nothing.
func TestResolvedAFailedFirstReadIsStaleUntilTheUplinkAppears(t *testing.T) {
	uplink := filepath.Join(t.TempDir(), "uplink.conf") // missing: the first read fails
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams, c.UpstreamsUnknown = func(a []netip.Addr) { told <- a }, true
	r := newTestResolved(c, true, uplink)
	firstResolvedRead(t, r)
	if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) || Unprotected(p) {
		t.Errorf("problem after a failed first read: %v", p)
	}
	tickResolved(t, r)
	toldNothing(t, told)
	if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) {
		t.Errorf("problem after another failed read: %v", p)
	}
	if err := os.WriteFile(uplink, []byte("nameserver 192.0.2.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tickResolved(t, r)
	select {
	case got := <-told:
		if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.53")}) {
			t.Errorf("told %v, want 192.0.2.53", got)
		}
	case <-time.After(time.Second):
		t.Fatal("never told the first good read")
	}
	if p := r.Problem(); p != nil {
		t.Errorf("problem after a good read: %v", p)
	}
	tickResolved(t, r)
	toldNothing(t, told)
	if p := r.Problem(); p != nil {
		t.Errorf("problem after an unchanged read: %v", p)
	}
}

// When the uplink file is readable at setup, its read is the first good
// one: it is told at once, with the stub and the node's own servers left
// out, and a later unchanged read tells nothing.
func TestResolvedTheFirstGoodReadAtSetupIsToldAtOnce(t *testing.T) {
	dir := t.TempDir()
	uplink := filepath.Join(dir, "uplink.conf")
	if err := os.WriteFile(uplink, []byte("nameserver 127.0.0.53\nnameserver 198.51.100.53\nnameserver 100.64.0.2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams, c.UpstreamsUnknown = func(a []netip.Addr) { told <- a }, true
	r := newTestResolved(c, true, uplink)
	firstResolvedRead(t, r)
	select {
	case got := <-told:
		if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("198.51.100.53")}) {
			t.Errorf("told %v, want 198.51.100.53", got)
		}
	case <-time.After(time.Second):
		t.Fatal("never told the read at setup")
	}
	if p := r.Problem(); p != nil {
		t.Errorf("problem after a good read: %v", p)
	}
	tickResolved(t, r)
	toldNothing(t, told)
}

// A failed read keeps the previous servers: a change read while the
// uplink file is readable is told, a later unreadable one tells nothing
// and keeps them, and its returning is told only when the servers
// changed.
func TestResolvedAFailedReadKeepsThePreviousServers(t *testing.T) {
	dir := t.TempDir()
	uplink := filepath.Join(dir, "uplink.conf")
	if err := os.WriteFile(uplink, []byte("nameserver 198.51.100.53\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams = func(a []netip.Addr) { told <- a }
	r := newTestResolved(c, true, uplink)
	firstResolvedRead(t, r)
	toldNothing(t, told)

	// resolved rewrote its list: told.
	if err := os.WriteFile(uplink, []byte("nameserver 198.51.100.99\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tickResolved(t, r)
	select {
	case got := <-told:
		if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("198.51.100.99")}) {
			t.Errorf("told %v, want 198.51.100.99", got)
		}
	case <-time.After(time.Second):
		t.Fatal("never told the change")
	}

	// The file vanishes: the read failed, the previous ones are kept.
	if err := os.Remove(uplink); err != nil {
		t.Fatal(err)
	}
	tickResolved(t, r)
	toldNothing(t, told)

	// It is back, unchanged: told nothing.
	if err := os.WriteFile(uplink, []byte("nameserver 198.51.100.99\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	tickResolved(t, r)
	toldNothing(t, told)
	if p := r.Problem(); p != nil {
		t.Errorf("problem after the file returned: %v", p)
	}
}
