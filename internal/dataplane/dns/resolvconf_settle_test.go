package dns

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The tests here write resolv.conf in place, the way busybox udhcpc's
// older script does (`echo -n > $RESOLV_CONF`, then one `echo … >>` per
// line), or through one open file, the way `cat >` does: the half-written
// file is what the watch must not take.

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

// overwriteInPlace writes s into the file at path through one open with
// O_TRUNC, as `cat > file` does: the same file, not a new one.
func overwriteInPlace(t *testing.T, path, s string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(s), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeInPlaceSlowly truncates path, pauses first, then appends
// renewedInPlace a line at a time, pausing after each line.
func writeInPlaceSlowly(t *testing.T, path string, first, pause time.Duration) {
	t.Helper()
	truncateFile(t, path)
	time.Sleep(first)
	for _, line := range []string{"search lan\n", "nameserver 192.0.2.7\n", "nameserver 2001:db8::7\n"} {
		appendFile(t, path, line)
		time.Sleep(pause)
	}
}

// startInPlace manages a resolv.conf holding isp, telling its upstreams
// on told.
func startInPlace(t *testing.T, timing resolvConfTiming) (string, *resolvConf, chan []netip.Addr) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	told := make(chan []netip.Addr, 64)
	c := testSystem
	c.Upstreams = func(a []netip.Addr) { told <- a }
	r, err := setResolvConfTimed(path, "", c, timing)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	return path, r, told
}

// hasChangeEvents skips a test that needs change notifications where
// there are none (the watch only polls there).
func hasChangeEvents(t *testing.T) {
	t.Helper()
	ch, closeWatch := watchFile(filepath.Join(t.TempDir(), "x"))
	closeWatch()
	if ch == nil {
		t.Skip("no change notifications here")
	}
}

// managedWith says the file at path is the managed one, with want as its
// original, pointing the OS at the node.
func managedWith(t *testing.T, path, want string) bool {
	t.Helper()
	got := readString(t, path)
	m := parseResolvConf([]byte(got))
	return m.managed && string(m.original) == want && slices.Equal(nameservers([]byte(got)), testSystem.Servers)
}

// takenBackWith waits until the managed file holds want as its original
// and points the OS at the node again.
func takenBackWith(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !managedWith(t, path, want) {
		if time.Now().After(deadline) {
			t.Fatalf("not taken back with %q as the original:\n%s", want, readString(t, path))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// toldOnly says want was told, and nothing else: no half-written file's
// servers before it.
func toldOnly(t *testing.T, told <-chan []netip.Addr, want []netip.Addr) {
	t.Helper()
	var all [][]netip.Addr
	select {
	case got := <-told:
		all = append(all, got)
	case <-time.After(5 * time.Second):
		t.Fatal("told nothing")
	}
	for done := false; !done; {
		select {
		case got := <-told:
			all = append(all, got)
		case <-time.After(200 * time.Millisecond):
			done = true
		}
	}
	for _, got := range all {
		if !slices.Equal(got, want) {
			t.Errorf("told %v, want only %v", all, want)
			return
		}
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

// restoredTo says Restore puts want back.
func restoredTo(t *testing.T, path string, r *resolvConf, want string) {
	t.Helper()
	if err := r.Restore(); err != nil {
		t.Fatal(err)
	}
	if got := readString(t, path); got != want {
		t.Errorf("restored\n%s\nwant\n%s", got, want)
	}
}

// checkInPlaceRenewal says the node ended with the writer's file as the
// original, told its servers and no half-written file's, reports no
// problem, and puts it back.
func checkInPlaceRenewal(t *testing.T, path string, r *resolvConf, told <-chan []netip.Addr) {
	t.Helper()
	takenBackWith(t, path, renewedInPlace)
	toldOnly(t, told, renewedInPlaceServers)
	if p := r.Problem(); p != nil {
		t.Errorf("problem %v", p)
	}
	restoredTo(t, path, r, renewedInPlace)
}

// Woken by change events only (the poll is out of the way): the close
// after the truncation wakes the watch, and the appends that follow are
// not lost to the managed file.
func TestResolvConfAnInPlaceWriterSettlesBeforeItIsRead(t *testing.T) {
	hasChangeEvents(t)
	path, r, told := startInPlace(t, resolvConfTiming{check: time.Hour, settle: time.Second, settleMax: 10 * time.Second})
	writeInPlaceSlowly(t, path, 50*time.Millisecond, 50*time.Millisecond)
	checkInPlaceRenewal(t, path, r, told)
}

// The poll reads the file empty between the truncation and the appends,
// and then each part as it grows: with no change events, a changed file
// is the only sign the write goes on, and the writer outlasts the settle.
func TestResolvConfAPollThatReadsAnInPlaceWriteEmptyWaits(t *testing.T) {
	path, r, told := startInPlace(t, resolvConfTiming{check: 20 * time.Millisecond, settle: 300 * time.Millisecond, settleMax: 10 * time.Second})
	writeInPlaceSlowly(t, path, 100*time.Millisecond, 150*time.Millisecond)
	checkInPlaceRenewal(t, path, r, told)
}

// A writer that keeps rewriting the same content keeps the settle going:
// each rewrite is a change event though every read finds the same file.
func TestResolvConfARewriteOfTheSameContentKeepsTheSettleGoing(t *testing.T) {
	hasChangeEvents(t)
	path, r, told := startInPlace(t, resolvConfTiming{check: time.Hour, settle: time.Second, settleMax: time.Minute})
	end := time.Now().Add(2500 * time.Millisecond)
	for i := 0; time.Now().Before(end); i++ {
		if i > 0 && parseResolvConf([]byte(readString(t, path))).managed {
			t.Fatal("taken back while the writer was still rewriting")
		}
		overwriteInPlace(t, path, renewedInPlace)
		time.Sleep(100 * time.Millisecond)
	}
	checkInPlaceRenewal(t, path, r, told)
}

// A writer that never goes quiet (another program fighting over the
// file) is taken back at the settle's cap, not when it stops.
func TestResolvConfAWriterThatNeverSettlesIsTakenBackAtTheCap(t *testing.T) {
	timing := resolvConfTiming{check: 20 * time.Millisecond, settle: 300 * time.Millisecond, settleMax: time.Second}
	path, _, _ := startInPlace(t, timing)
	start := time.Now()
	var takenBack time.Duration
	for i := 0; time.Since(start) < 3*time.Second; i++ {
		if takenBack == 0 && i > 0 && parseResolvConf([]byte(readString(t, path))).managed {
			takenBack = time.Since(start)
		}
		overwriteInPlace(t, path, fmt.Sprintf("nameserver 192.0.2.%d\n", 10+i%200))
		time.Sleep(100 * time.Millisecond)
	}
	switch {
	case takenBack == 0:
		t.Fatal("never taken back while the writer ran")
	case takenBack > timing.settleMax+timing.settle:
		t.Errorf("taken back after %v, want within %v", takenBack, timing.settleMax+timing.settle)
	}
}

// While another program's write hasn't settled for longer than the
// settle, the node says it isn't protected; once taken back, it is.
func TestResolvConfProblemReportsAWriteThatDoesNotSettle(t *testing.T) {
	path, r, told := startInPlace(t, resolvConfTiming{check: 20 * time.Millisecond, settle: 200 * time.Millisecond, settleMax: time.Hour})
	start := time.Now()
	sawUnprotected := false
	for i := 0; time.Since(start) < 1500*time.Millisecond; i++ {
		overwriteInPlace(t, path, fmt.Sprintf("nameserver 192.0.2.%d\n", 10+i%200))
		time.Sleep(50 * time.Millisecond)
		if time.Since(start) > 800*time.Millisecond && Unprotected(r.Problem()) {
			sawUnprotected = true
		}
	}
	if !sawUnprotected {
		t.Error("no unprotected problem while the write went on")
	}
	overwriteInPlace(t, path, renewedInPlace)
	checkInPlaceRenewal(t, path, r, told)
}

// A file renamed into place is complete at its first sight: it is taken
// at once, with no settle.
func TestResolvConfAFileRenamedInIsTakenAtOnce(t *testing.T) {
	path, r, told := startInPlace(t, resolvConfTiming{check: 20 * time.Millisecond, settle: time.Hour, settleMax: time.Hour})
	writeFileAtomic(t, path, renewedInPlace)
	checkInPlaceRenewal(t, path, r, told)
}

// An Update the watch hasn't seen a write before (no poll, and an open
// with O_TRUNC makes no change event before its close) reads the file
// itself, and leaves a write in progress to the watch: the configuration
// is the new one, the original the writer's whole file.
func TestResolvConfAnUpdateDuringAnUnseenWriteWaitsForIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		finish func(t *testing.T, path string, update func())
	}{
		{"appends", func(t *testing.T, path string, update func()) {
			truncateFile(t, path)
			update()
			appendFile(t, path, renewedInPlace)
		}},
		{"one open", func(t *testing.T, path string, update func()) {
			writeThroughOneOpen(t, path, update)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, r, told := startInPlace(t, resolvConfTiming{check: time.Hour, settle: 300 * time.Millisecond, settleMax: 10 * time.Second})
			tc.finish(t, path, func() { updateSearch(t, r, told) })
			checkUpdatedRenewal(t, path, r, told)
		})
	}
}

// An Update while the watch settles a write leaves the rewrite to it.
func TestResolvConfAnUpdateWhileAWriteSettlesWaitsForIt(t *testing.T) {
	path, r, told := startInPlace(t, resolvConfTiming{check: 20 * time.Millisecond, settle: 2 * time.Second, settleMax: 10 * time.Second})
	writeThroughOneOpen(t, path, func() {
		time.Sleep(100 * time.Millisecond) // polls read the file empty: a settle begins
		updateSearch(t, r, told)
	})
	checkUpdatedRenewal(t, path, r, told)
}

// writeThroughOneOpen writes renewedInPlace the way `cat > file` does,
// one open with O_TRUNC, running during between the truncation and the
// write.
func writeThroughOneOpen(t *testing.T, path string, during func()) {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	during()
	_, err = f.WriteString(renewedInPlace)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
}

// updateSearch updates r to search other.internal.
func updateSearch(t *testing.T, r *resolvConf, told chan []netip.Addr) {
	t.Helper()
	next := testSystem
	next.Search = []string{"other.internal"}
	next.Upstreams = func(a []netip.Addr) { told <- a }
	if err := r.Update(next); err != nil {
		t.Fatal(err)
	}
}

// checkUpdatedRenewal is checkInPlaceRenewal after updateSearch.
func checkUpdatedRenewal(t *testing.T, path string, r *resolvConf, told <-chan []netip.Addr) {
	t.Helper()
	takenBackWith(t, path, renewedInPlace)
	if got := readString(t, path); !strings.Contains(got, "\nsearch other.internal\n") {
		t.Errorf("the update is lost:\n%s", got)
	}
	checkInPlaceRenewal(t, path, r, told)
}

// A writer that pauses longer than the settle, and goes on past the cap,
// has its first part taken; what it appends then lands in the managed
// file and joins the original, so its servers are not lost.
func TestResolvConfASlowWriterPastTheCapKeepsItsServers(t *testing.T) {
	path, r, told := startInPlace(t, resolvConfTiming{check: 20 * time.Millisecond, settle: 100 * time.Millisecond, settleMax: 300 * time.Millisecond})
	writeInPlaceSlowly(t, path, 400*time.Millisecond, 400*time.Millisecond)
	takenBackWith(t, path, renewedInPlace)
	if got := lastTold(t, told); !slices.Equal(got, renewedInPlaceServers) {
		t.Errorf("told %v last, want %v", got, renewedInPlaceServers)
	}
	restoredTo(t, path, r, renewedInPlace)
}

// A line appended to the managed file by hand joins the original: it is
// told, and Restore puts it back.
func TestResolvConfAHandAppendSurvivesRestore(t *testing.T) {
	path, r, told := startInPlace(t, resolvConfTiming{check: 20 * time.Millisecond, settle: 100 * time.Millisecond, settleMax: time.Second})
	appendFile(t, path, "nameserver 192.0.2.9\n")
	want := isp + "nameserver 192.0.2.9\n"
	takenBackWith(t, path, want)
	toldOnly(t, told, []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("2001:db8::53"), netip.MustParseAddr("192.0.2.9")})
	restoredTo(t, path, r, want)
}

// An Update left to the watch whose write then fails is not lost: the
// watch logs it, and Problem reports it.
func TestResolvConfADeferredUpdateThatFailsShowsInProblem(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes into a read-only directory")
	}
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	var log lockedBuffer
	told := make(chan []netip.Addr, 8)
	c := testSystem
	c.Upstreams = func(a []netip.Addr) { told <- a }
	c.Log = slog.New(slog.NewTextHandler(&log, nil))
	r, err := setResolvConfTimed(path, "", c, resolvConfTiming{check: 20 * time.Millisecond, settle: 100 * time.Millisecond, settleMax: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	dir := filepath.Dir(path)
	// The rewrite's temporary file can't be created: the rename fails.
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	writeThroughOneOpen(t, path, func() {
		next := c
		next.Search = []string{"other.internal"}
		if err := r.Update(next); err != nil {
			t.Fatal(err)
		}
	})
	// The failure is logged after the lock is released: wait for both.
	deadline := time.Now().Add(5 * time.Second)
	for {
		p := r.Problem()
		logged := strings.Contains(log.String(), "taking back resolv.conf failed")
		if Unprotected(p) && strings.Contains(p.Error(), "rewriting") && logged {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("after the failed rewrite: problem %v, logged %t:\n%s", p, logged, log.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Restore ends the management: an Update after it fails and leaves the
// restored file alone.
func TestResolvConfAnUpdateAfterRestoreFails(t *testing.T) {
	path, r, told := startInPlace(t, resolvConfTiming{check: 20 * time.Millisecond, settle: 100 * time.Millisecond, settleMax: time.Second})
	restoredTo(t, path, r, isp)
	next := testSystem
	next.Upstreams = func(a []netip.Addr) { told <- a }
	if err := r.Update(next); !errors.Is(err, errRestored) {
		t.Errorf("Update after Restore: %v, want %v", err, errRestored)
	}
	if got := readString(t, path); got != isp {
		t.Errorf("Update after Restore wrote\n%s", got)
	}
}

// An empty /etc/resolv.conf is a valid configuration (the resolver then
// asks the local host): one that stays empty past the settle is the new
// original, naming no server, and Restore puts it back empty.
func TestResolvConfAnEmptyFileThatStaysIsTheOriginal(t *testing.T) {
	path, r, told := startInPlace(t, resolvConfTiming{check: 20 * time.Millisecond, settle: 100 * time.Millisecond, settleMax: time.Second})
	truncateFile(t, path)
	takenBackWith(t, path, "")
	toldNothing(t, told) // the previous upstreams are kept
	if p := r.Problem(); !errors.Is(p, ErrNoSystemUpstream) || Unprotected(p) {
		t.Errorf("problem %v, want no system upstream only", p)
	}
	restoredTo(t, path, r, "")
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
	r, err := setResolvConfTimed(path, "", c, resolvConfTiming{check: time.Hour, settle: time.Hour, settleMax: time.Hour})
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
