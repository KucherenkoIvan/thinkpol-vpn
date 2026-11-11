package dns

import (
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The tests here write resolv.conf in place, the way busybox udhcpc's
// script does (`echo -n > $RESOLV_CONF`, then one `echo … >>` per
// line): the half-written file is what the watch must not take.

const renewedInPlace = "search lan\nnameserver 192.0.2.7\nnameserver 2001:db8::7\n"

var renewedInPlaceServers = []netip.Addr{netip.MustParseAddr("192.0.2.7"), netip.MustParseAddr("2001:db8::7")}

// truncateFile empties a file in place, as `> file` does.
func truncateFile(t *testing.T, path string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
}

// appendFile appends to a file, opening it again, as `>> file` does.
func appendFile(t *testing.T, path, s string) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, err = f.WriteString(s)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
}

// writeInPlaceSlowly truncates path, then appends renewedInPlace a line
// at a time, pausing after each step.
func writeInPlaceSlowly(t *testing.T, path string, pause time.Duration) {
	t.Helper()
	truncateFile(t, path)
	time.Sleep(pause)
	for _, line := range []string{"search lan\n", "nameserver 192.0.2.7\n", "nameserver 2001:db8::7\n"} {
		appendFile(t, path, line)
		time.Sleep(pause)
	}
}

// startInPlace manages a resolv.conf holding isp, telling its upstreams
// on told.
func startInPlace(t *testing.T, check, settle time.Duration) (string, *resolvConf, chan []netip.Addr) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	told := make(chan []netip.Addr, 16)
	c := testSystem
	c.Upstreams = func(a []netip.Addr) { told <- a }
	r, err := startResolvConf(path, "", c, check, settle)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	return path, r, told
}

// takenBackWith waits until the managed file holds want as its original
// and points the OS at the node again.
func takenBackWith(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := readString(t, path)
		m := parseResolvConf([]byte(got))
		if m.managed && string(m.original) == want && slices.Equal(nameservers([]byte(got)), testSystem.Servers) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("not taken back with the writer's file as the original:\n%s", got)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// lastTold is the last thing told within a while, failing if nothing was.
func lastTold(t *testing.T, told <-chan []netip.Addr) []netip.Addr {
	t.Helper()
	var last []netip.Addr
	select {
	case last = <-told:
	case <-time.After(5 * time.Second):
		t.Fatal("told nothing")
	}
	for {
		select {
		case last = <-told:
		case <-time.After(200 * time.Millisecond):
			return last
		}
	}
}

// checkInPlaceRenewal says the node ended with the writer's file as the
// original, told its servers, reports no problem, and puts it back.
func checkInPlaceRenewal(t *testing.T, path string, r *resolvConf, told <-chan []netip.Addr) {
	t.Helper()
	takenBackWith(t, path, renewedInPlace)
	if got := lastTold(t, told); !slices.Equal(got, renewedInPlaceServers) {
		t.Errorf("told %v last, want %v", got, renewedInPlaceServers)
	}
	if p := r.Problem(); p != nil {
		t.Errorf("problem %v", p)
	}
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != renewedInPlace {
		t.Errorf("restored\n%s\nwant the writer's\n%s", got, renewedInPlace)
	}
}

// Woken by change events only (the poll is out of the way): the close
// after the truncation wakes the watch, and the appends that follow are
// not lost to the managed file.
func TestResolvConfAnInPlaceWriterSettlesBeforeItIsRead(t *testing.T) {
	ch, closeWatch := watchFile(filepath.Join(t.TempDir(), "x"))
	closeWatch()
	if ch == nil {
		t.Skip("no change notifications here")
	}
	path, r, told := startInPlace(t, time.Hour, 300*time.Millisecond)
	writeInPlaceSlowly(t, path, 50*time.Millisecond)
	checkInPlaceRenewal(t, path, r, told)
}

// The poll reads the file empty between the truncation and the appends:
// the empty file is not taken as the original.
func TestResolvConfAPollThatReadsAnInPlaceWriteEmptyWaits(t *testing.T) {
	path, r, told := startInPlace(t, 20*time.Millisecond, 300*time.Millisecond)
	truncateFile(t, path)
	time.Sleep(100 * time.Millisecond) // several polls read it empty
	for _, line := range []string{"search lan\n", "nameserver 192.0.2.7\n", "nameserver 2001:db8::7\n"} {
		appendFile(t, path, line)
		time.Sleep(50 * time.Millisecond)
	}
	checkInPlaceRenewal(t, path, r, told)
}

// An Update while a write settles leaves the rewrite to the watch: the
// configuration is the new one, the original the writer's whole file.
func TestResolvConfAnUpdateWhileAWriteSettlesWaitsForIt(t *testing.T) {
	path, r, told := startInPlace(t, 20*time.Millisecond, 300*time.Millisecond)
	truncateFile(t, path)
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		settling := r.settling
		r.mu.Unlock()
		if settling {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the truncation never started a settle")
		}
		time.Sleep(5 * time.Millisecond)
	}
	next := testSystem
	next.Search = []string{"other.internal"}
	next.Upstreams = func(a []netip.Addr) { told <- a }
	if err := r.Update(next); err != nil {
		t.Fatal(err)
	}
	appendFile(t, path, renewedInPlace)
	takenBackWith(t, path, renewedInPlace)
	if got := readString(t, path); !strings.Contains(got, "\nsearch other.internal\n") {
		t.Errorf("the update is lost:\n%s", got)
	}
	if got := lastTold(t, told); !slices.Equal(got, renewedInPlaceServers) {
		t.Errorf("told %v last, want %v", got, renewedInPlaceServers)
	}
}

// An empty /etc/resolv.conf is a valid configuration (the resolver then
// asks the local host): one that stays empty past the settle is the new
// original, naming no server, and Restore puts it back empty.
func TestResolvConfAnEmptyFileThatStaysIsTheOriginal(t *testing.T) {
	path, r, told := startInPlace(t, 20*time.Millisecond, 100*time.Millisecond)
	truncateFile(t, path)
	takenBackWith(t, path, "")
	toldNothing(t, told) // the previous upstreams are kept
	if p := r.Problem(); !errors.Is(p, ErrNoSystemUpstream) || Unprotected(p) {
		t.Errorf("problem %v, want no system upstream only", p)
	}
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != "" {
		t.Errorf("restored %q, want the empty file", got)
	}
}

// While the first read is owed, a managed file whose original was a link
// reads the link's target; an empty target is no read, since the managed
// file would record it as no original and the retries would end. The
// target filled in later is told.
func TestResolvConfAnEmptyLinkTargetIsNotAGoodRead(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "real.conf")
	path := filepath.Join(dir, "resolv.conf")
	if err := os.Symlink("real.conf", path); err != nil { // dangling at setup
		t.Fatal(err)
	}
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams, c.UpstreamsUnknown = func(a []netip.Addr) { told <- a }, true
	r, err := startResolvConf(path, "", c, time.Hour, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	if err := os.WriteFile(target, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	applyOnce(t, r)
	toldNothing(t, told)
	if p := r.Problem(); !errors.Is(p, ErrUpstreamsStale) {
		t.Errorf("problem after an empty target: %v", p)
	}
	writeFileAtomic(t, target, "nameserver 192.0.2.53\n")
	applyOnce(t, r)
	select {
	case got := <-told:
		if !slices.Equal(got, []netip.Addr{netip.MustParseAddr("192.0.2.53")}) {
			t.Errorf("told %v, want 192.0.2.53", got)
		}
	case <-time.After(time.Second):
		t.Fatal("never told the filled target")
	}
	if p := r.Problem(); p != nil {
		t.Errorf("problem after a good read: %v", p)
	}
}
