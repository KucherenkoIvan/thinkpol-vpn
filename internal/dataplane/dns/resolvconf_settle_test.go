package dns

import (
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
	start, closeWatch := watchFile(filepath.Join(t.TempDir(), "x"))
	ch := start()
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
// file) is taken back at the settle's cap, not when it stops. The writer
// writes in place, so only the node's take-back, a rename, gives the
// file it opens another inode: the take-back came after the open before.
// (Reading the file for the managed one instead could miss it: the
// writer's next open truncates the node's file before it is read.)
func TestResolvConfAWriterThatNeverSettlesIsTakenBackAtTheCap(t *testing.T) {
	timing := resolvConfTiming{check: 20 * time.Millisecond, settle: 300 * time.Millisecond, settleMax: time.Second}
	path, _, _ := startInPlace(t, timing)
	start := time.Now()
	var prev fs.FileInfo
	var prevOpened time.Time
	for i := 0; time.Since(start) < 3*time.Second; i++ {
		opened := time.Now()
		fi := overwriteInPlaceStat(t, path, fmt.Sprintf("nameserver 192.0.2.%d\n", 10+i%200))
		if prev != nil && !os.SameFile(prev, fi) {
			if after := prevOpened.Sub(start); after > timing.settleMax+timing.settle {
				t.Errorf("taken back after %v, want within %v", after, timing.settleMax+timing.settle)
			}
			return
		}
		prev, prevOpened = fi, opened
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("never taken back while the writer ran")
}

// overwriteInPlaceStat is overwriteInPlace through one open file, and
// that file's info.
func overwriteInPlaceStat(t *testing.T, path, s string) fs.FileInfo {
	t.Helper()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := f.Stat()
	if err == nil {
		_, err = f.WriteString(s)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
	return fi
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

// A file renamed into place is complete at its first sight: the rename's
// change event takes it at once, with no settle.
func TestResolvConfAFileRenamedInIsTakenAtOnce(t *testing.T) {
	hasChangeEvents(t)
	path, r, told := startInPlace(t, resolvConfTiming{check: time.Hour, settle: time.Hour, settleMax: time.Hour})
	writeFileAtomic(t, path, renewedInPlace)
	checkInPlaceRenewal(t, path, r, told)
}

// withWatchHook runs setUp with the file at path when the watch of a
// resolv.conf is set up, and started when it is started, each before the
// real step. Either may be nil.
func withWatchHook(t *testing.T, setUp, started func(path string)) {
	t.Helper()
	watch := watchResolvConf
	t.Cleanup(func() { watchResolvConf = watch })
	watchResolvConf = func(path string) (func() <-chan bool, func()) {
		if setUp != nil {
			setUp(path)
		}
		start, closeWatch := watch(path)
		return func() <-chan bool {
			if started != nil {
				started(path)
			}
			return start()
		}, closeWatch
	}
}

// The watch is set up before the take-over writes the file, and so before
// it returns: another program's file renamed in right after the
// take-over (reacting to the new TUN) is seen at once, not at the poll.
func TestResolvConfIsWatchedBeforeTheTakeOverWrites(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(path, []byte(isp), 0o644); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var atSetUp []byte
	setUp, started := false, false
	withWatchHook(t, func(path string) {
		b, _ := os.ReadFile(path)
		mu.Lock()
		defer mu.Unlock()
		atSetUp, setUp = b, true
	}, func(string) {
		mu.Lock()
		defer mu.Unlock()
		started = true
	})
	r, err := setResolvConfTimed(path, "", testSystem, resolvConfTiming{check: time.Hour, settle: time.Hour, settleMax: time.Hour})
	mu.Lock()
	gotSetUp, gotStarted, gotAtSetUp := setUp, started, string(atSetUp)
	mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	if !gotSetUp || !gotStarted {
		t.Fatalf("set up %t, started %t when the take-over returned", gotSetUp, gotStarted)
	}
	if gotAtSetUp != isp {
		t.Fatalf("watched only after the take-over wrote the file; it held:\n%s", gotAtSetUp)
	}
	if !managedWith(t, path, isp) {
		t.Fatalf("not taken over:\n%s", readString(t, path))
	}
}

// Another program's file renamed in after the take-over wrote the file,
// but before the watch started, is not lost to the poll: its event, one
// signal with the take-over's own, is no rename, so it settles.
func TestResolvConfAFileRenamedInDuringTheTakeOverIsSeen(t *testing.T) {
	hasChangeEvents(t)
	withWatchHook(t, nil, func(path string) { writeFileAtomic(t, path, renewedInPlace) })
	path, r, told := startInPlace(t, resolvConfTiming{check: time.Hour, settle: 300 * time.Millisecond, settleMax: 10 * time.Second})
	checkInPlaceRenewal(t, path, r, told)
}

// A file another program creates at the path after the take-over wrote
// it, before the watch started, settles: the take-over's own rename
// doesn't make the empty file a renamed-in one.
func TestResolvConfAFileCreatedDuringTheTakeOverSettles(t *testing.T) {
	hasChangeEvents(t)
	var f *os.File
	withWatchHook(t, nil, func(path string) {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		var err error
		if f, err = os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644); err != nil {
			t.Fatal(err)
		}
	})
	path, r, told := startInPlace(t, resolvConfTiming{check: time.Hour, settle: 300 * time.Millisecond, settleMax: 10 * time.Second})
	time.Sleep(100 * time.Millisecond) // the creation is seen, empty
	_, err := f.WriteString(renewedInPlace)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		t.Fatal(err)
	}
	checkInPlaceRenewal(t, path, r, told)
}

// The take-over's own write raises a change event, the watch being set
// up before it: the watch reads it as the node's own file, writes
// nothing (no event follows it) and reports no problem.
func TestResolvConfTheTakeOverOwnEventIsNotAnotherProgramsWrite(t *testing.T) {
	hasChangeEvents(t)
	var mu sync.Mutex
	events := 0
	forwarded := make(chan struct{}, 64)
	ctx := t.Context()
	watch := watchResolvConf
	t.Cleanup(func() { watchResolvConf = watch })
	watchResolvConf = func(path string) (func() <-chan bool, func()) {
		start, closeWatch := watch(path)
		return func() <-chan bool {
			ch := start()
			mine := make(chan bool) // unbuffered: a send ends once the watch took it
			go func() {
				for {
					var renamed bool
					select {
					case renamed = <-ch:
					case <-ctx.Done():
						return
					}
					mu.Lock()
					events++
					mu.Unlock()
					select {
					case mine <- renamed:
						forwarded <- struct{}{}
					case <-ctx.Done():
						return
					}
				}
			}()
			return mine
		}, closeWatch
	}
	path, r, _ := startInPlace(t, resolvConfTiming{check: time.Hour, settle: time.Hour, settleMax: time.Hour})
	written, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-forwarded:
	case <-time.After(5 * time.Second):
		t.Fatal("the take-over's own write raised no change event the watch took")
	}
	time.Sleep(300 * time.Millisecond) // a rewrite of its own would raise another
	mu.Lock()
	n := events
	mu.Unlock()
	if n != 1 {
		t.Errorf("%d change events after the take-over, want its own one only: the watch wrote the file again", n)
	}
	if fi, err := os.Lstat(path); err != nil || !os.SameFile(fi, written) || !fi.ModTime().Equal(written.ModTime()) {
		t.Errorf("the file was written again after the take-over (err %v)", err)
	}
	if p := r.Problem(); p != nil {
		t.Errorf("problem %v", p)
	}
	if !managedWith(t, path, isp) {
		t.Errorf("not the take-over's file:\n%s", readString(t, path))
	}
}

// A file created at the path is another file than the node's before its
// first byte is written (rm then `cat >`, an editor writing a new file,
// install): the change event of its creation and the poll find it new
// and empty, and it settles like a write in place. The removal raises no
// watched event, so with change events only nothing happens until the
// creation; removed a while first, the new file is less likely to get
// the removed one's inode number, which would make it look like the
// node's file and settle whatever the rule for a new file.
func TestResolvConfAFileCreatedAtThePathSettles(t *testing.T) {
	for _, tc := range []struct {
		name    string
		events  bool
		removed time.Duration // how long there is no file
	}{
		{"change events", true, 0},
		{"change events, removed a while", true, 150 * time.Millisecond},
		{"poll", false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := 20 * time.Millisecond
			if tc.events {
				hasChangeEvents(t)
				check = time.Hour
			}
			path, r, told := startInPlace(t, resolvConfTiming{check: check, settle: 300 * time.Millisecond, settleMax: 10 * time.Second})
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			time.Sleep(tc.removed)
			f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
			if err != nil {
				t.Fatal(err)
			}
			time.Sleep(100 * time.Millisecond) // the creation is seen, empty
			_, err = f.WriteString(renewedInPlace)
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if err != nil {
				t.Fatal(err)
			}
			checkInPlaceRenewal(t, path, r, told)
		})
	}
}

// Problem follows one rule, with no model of the writer: unprotected
// while another program's file is in place and for the hold after each
// take-back. So a writer faster than the settle (taken back at the cap),
// one whose every write settles, and one that writes every few seconds
// are all reported for as long as they write, and Problem clears within
// the hold once they stop. The product's timings, polled often.
func TestResolvConfAWriterFightingOverTheFileIsUnprotectedAtAnyPeriod(t *testing.T) {
	timing := resolvConfTimes
	timing.check = 20 * time.Millisecond
	for _, period := range []time.Duration{100 * time.Millisecond, 600 * time.Millisecond, 3 * time.Second} {
		t.Run(period.String(), func(t *testing.T) {
			t.Parallel()
			path, r, _ := startInPlace(t, timing)
			start := time.Now()
			next := start
			for now := start; now.Sub(start) < 3200*time.Millisecond; now = time.Now() {
				if !now.Before(next) {
					overwriteInPlace(t, path, renewedInPlace)
					next = next.Add(period)
				}
				// The watch sees the first write within a poll.
				if now.Sub(start) > 300*time.Millisecond {
					if p := r.Problem(); !Unprotected(p) {
						t.Fatalf("problem %v at %v while the writer goes on, want unprotected", p, now.Sub(start).Round(time.Millisecond))
					}
				}
				time.Sleep(10 * time.Millisecond)
			}
			takenBackWith(t, path, renewedInPlace)
			deadline := time.Now().Add(timing.hold + time.Second)
			for p := r.Problem(); p != nil; p = r.Problem() {
				if time.Now().After(deadline) {
					t.Fatalf("problem %v a hold after the writer stopped", p)
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
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
		if !Deferred(r) {
			t.Error("an Update during a settle is not reported deferred")
		}
	})
	checkUpdatedRenewal(t, path, r, told)
	if Deferred(r) {
		t.Error("still deferred after the settle")
	}
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

// A rewrite that fails partway (a bind mount's write in place: the file
// truncated, then part of the new content) leaves a file that starts
// with what the node wrote before: the rest is the node's own lines, not
// another program's appended ones, and never joins the original.
func TestResolvConfAPartialRewriteIsNotTakenAsAppendedLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "resolv.conf") // no file: the original is empty
	c := testSystem
	c.Search = nil
	r, err := setResolvConfTimed(path, "", c, resolvConfTiming{check: 20 * time.Millisecond, settle: 50 * time.Millisecond, settleMax: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Restore() })
	r.mu.Lock()
	failed := false
	r.rewrite = func(path string, f resolvConfFile, content []byte) error {
		if failed {
			return rewriteResolvConf(path, f, content)
		}
		failed = true
		// The node's servers, then the write fails before the search line.
		end := bytes.Index(content, []byte("search "))
		if err := os.WriteFile(path, content[:end], 0o644); err != nil {
			return err
		}
		return partialWriteError{errors.New("injected: write failed partway")}
	}
	r.mu.Unlock()
	next := c
	next.Servers = append(slices.Clone(c.Servers), netip.MustParseAddr("100.64.0.3"))
	next.Search = []string{"home.internal"}
	if err := r.Update(next); err == nil {
		t.Fatal("the injected failure is lost")
	}
	deadline := time.Now().Add(5 * time.Second)
	for r.Problem() != nil {
		if time.Now().After(deadline) {
			t.Fatalf("not rewritten after the failure: problem %v", r.Problem())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if m := parseResolvConf([]byte(readString(t, path))); len(m.original) != 0 {
		t.Errorf("the node's own lines joined the original: %q", m.original)
	}
	restoredTo(t, path, r, "")
}

// A rewrite whose new file failed before its rename (no space for it,
// no permission) left the path as it was: a line appended by hand before
// the next rewrite is the hand's, and joins the original.
func TestResolvConfARewriteThatFailedBeforeItsRenameKeepsAHandAppend(t *testing.T) {
	path, r, told := startInPlace(t, resolvConfTiming{check: 20 * time.Millisecond, settle: 100 * time.Millisecond, settleMax: time.Second})
	r.mu.Lock()
	failed := false
	r.rewrite = func(path string, f resolvConfFile, content []byte) error {
		if failed {
			return rewriteResolvConf(path, f, content)
		}
		failed = true
		appendFile(t, path, "nameserver 192.0.2.9\n")
		return errors.New("injected: no space for the new file")
	}
	r.mu.Unlock()
	next := testSystem
	next.Search = []string{"other.internal"}
	next.Upstreams = func(a []netip.Addr) { told <- a }
	if err := r.Update(next); err == nil {
		t.Fatal("the injected failure is lost")
	}
	want := isp + "nameserver 192.0.2.9\n"
	takenBackWith(t, path, want)
	restoredTo(t, path, r, want)
}

// A rewrite in place that failed partway can end inside the original's
// lines: the original kept in memory is taken, not what is left of it.
func TestResolvConfARewriteThatFailedPartwayKeepsTheWholeOriginal(t *testing.T) {
	path, r, _ := startInPlace(t, resolvConfTiming{check: 20 * time.Millisecond, settle: 100 * time.Millisecond, settleMax: time.Second})
	r.mu.Lock()
	failed := false
	r.rewrite = func(path string, f resolvConfFile, content []byte) error {
		if failed {
			return rewriteResolvConf(path, f, content)
		}
		failed = true
		// Cut inside the original's last line, its options.
		if err := os.WriteFile(path, content[:len(content)-len("attempts:2\n")], 0o644); err != nil {
			return err
		}
		return partialWriteError{errors.New("injected: write failed partway")}
	}
	r.mu.Unlock()
	next := testSystem
	next.Search = []string{"other.internal"}
	if err := r.Update(next); err == nil {
		t.Fatal("the injected failure is lost")
	}
	takenBackWith(t, path, isp)
	restoredTo(t, path, r, isp)
}

// A change signal that came while the watch read the file joins the
// event that woke it: a rename stays a rename only if the pending change
// is one too; a wake with no change event (a poll, the quiet timer)
// takes the pending change as it is; Update's wake is never a rename.
func TestResolvConfWatchTakesInAChangeThatCameDuringTheRead(t *testing.T) {
	renamed := event{changed: true, renamed: true}
	for _, tc := range []struct {
		name    string
		ev      event
		pending []bool
		want    event
	}{
		{"rename, nothing pending", renamed, nil, renamed},
		{"rename, a rename pending", renamed, []bool{true}, renamed},
		{"rename, a write pending", renamed, []bool{false}, event{changed: true}},
		{"Update's wake, a rename pending", event{changed: true}, []bool{true}, event{changed: true}},
		{"poll, a rename pending", event{}, []bool{true}, renamed},
		{"quiet ended, a write pending", event{quietEnded: true}, []bool{false}, event{changed: true, quietEnded: true}},
		{"poll, nothing pending", event{}, nil, event{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ch := make(chan bool, 1)
			for _, p := range tc.pending {
				ch <- p
			}
			got, took := withPending(tc.ev, ch)
			if got != tc.want || took != (len(tc.pending) > 0) {
				t.Errorf("got %+v, took %t; want %+v, took %t", got, took, tc.want, len(tc.pending) > 0)
			}
		})
	}
	if got, took := withPending(renamed, nil); got != renamed || took {
		t.Errorf("with no change events: got %+v, took %t; want %+v", got, took, renamed)
	}
}

// A change signal taken in after a read makes the watch read the file
// again: another program's file renamed in after a read of the node's own
// is judged by a read that sees it, not taken for the node's own.
func TestResolvConfWatchReadsAgainAfterTakingInAChange(t *testing.T) {
	own := resolvConfFile{content: []byte("own"), read: true}
	theirs := resolvConfFile{content: []byte("theirs"), read: true}
	ch := make(chan bool, 1)
	reads := 0
	read := func() (resolvConfFile, error) {
		reads++
		if reads == 1 {
			ch <- true // renamed in right after this read
			return own, nil
		}
		return theirs, nil
	}
	ev, f, err := readJudged(read, event{}, ch)
	if err != nil || string(f.content) != "theirs" || ev != (event{changed: true, renamed: true}) {
		t.Errorf("judged %q with %+v (err %v), want the file renamed in with a rename", f.content, ev, err)
	}
	// Signals that keep coming end the reads at the bound; the last one
	// stays pending, for the next wake.
	reads = 0
	endless := func() (resolvConfFile, error) {
		reads++
		ch <- false
		return own, nil
	}
	if _, _, err := readJudged(endless, event{}, ch); err != nil {
		t.Fatal(err)
	}
	if reads != maxRereads+1 || len(ch) != 1 {
		t.Errorf("%d reads, %d signals pending; want %d and 1", reads, len(ch), maxRereads+1)
	}
}

// failPartway makes r's rewrites fail partway: each leaves the first cut
// bytes of what it would write, the way a write in place that runs out
// of space does, until the returned func lets them succeed. It counts the
// rewrites tried.
func failPartway(t *testing.T, r *resolvConf, cut func(content []byte) int) (succeed func(), tries func() int) {
	t.Helper()
	var mu sync.Mutex
	failing, n := true, 0
	r.mu.Lock()
	r.rewrite = func(path string, f resolvConfFile, content []byte) error {
		mu.Lock()
		fail := failing
		n++
		mu.Unlock()
		if !fail {
			return rewriteResolvConf(path, f, content)
		}
		if err := os.WriteFile(path, content[:cut(content)], 0o644); err != nil {
			return err
		}
		return partialWriteError{errors.New("injected: write failed partway")}
	}
	r.mu.Unlock()
	return func() { mu.Lock(); failing = false; mu.Unlock() },
		func() int { mu.Lock(); defer mu.Unlock(); return n }
}

// readUnderLock reads the file at path with r.mu held, as the watch
// does: a failing rewrite the poll retries truncates the file before it
// writes it, and a read in between finds it empty.
func readUnderLock(t *testing.T, r *resolvConf, path string) string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	return readString(t, path)
}

// A rewrite in place that failed partway can leave the file empty or cut
// inside the header line, which no longer reads as managed: it is the
// node's own write all the same, retried with the original kept in
// memory, not another program's write to settle, take as the original
// and report (the hold is an hour here: a take-back would show).
func TestResolvConfARewriteCutBeforeItsHeaderEndsKeepsTheOriginal(t *testing.T) {
	for _, tc := range []struct {
		name string
		cut  func([]byte) int
	}{
		{"cut at 0 bytes", func([]byte) int { return 0 }},
		{"cut inside the header", func([]byte) int { return len(resolvConfHeader) / 2 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path, r, _ := startInPlace(t, resolvConfTiming{check: 50 * time.Millisecond, settle: 100 * time.Millisecond, settleMax: time.Second, hold: time.Hour})
			succeed, _ := failPartway(t, r, tc.cut)
			next := testSystem
			next.Search = []string{"other.internal"}
			if err := r.Update(next); err == nil {
				t.Fatal("the injected failure is lost")
			}
			time.Sleep(150 * time.Millisecond) // retried, still failing
			if !errors.Is(r.Problem(), ErrUnprotected) {
				t.Errorf("a failing rewrite: problem %v", r.Problem())
			}
			succeed()
			deadline := time.Now().Add(5 * time.Second)
			for !managedWith(t, path, isp) || r.Problem() != nil {
				if time.Now().After(deadline) {
					t.Fatalf("not rewritten with the original after the failure: problem %v\n%s", r.Problem(), readString(t, path))
				}
				time.Sleep(20 * time.Millisecond)
			}
			restoredTo(t, path, r, isp)
		})
	}
}

// A rewrite in place that keeps failing partway inside the original's
// lines leaves the original cut short in the file: Restore puts back the
// whole one held in memory. Its own change events don't make it retry at
// once: a failing write retries on the poll.
func TestResolvConfRestoreAfterARewriteFailedPartwayPutsBackTheWholeOriginal(t *testing.T) {
	path, r, _ := startInPlace(t, resolvConfTiming{check: 100 * time.Millisecond, settle: 100 * time.Millisecond, settleMax: time.Second, hold: time.Hour})
	_, tries := failPartway(t, r, func(content []byte) int { return len(content) - len("attempts:2\n") })
	next := testSystem
	next.Search = []string{"other.internal"}
	if err := r.Update(next); err == nil {
		t.Fatal("the injected failure is lost")
	}
	time.Sleep(500 * time.Millisecond)
	if n := tries(); n > 10 {
		t.Errorf("%d rewrites tried in 500 ms with a 100 ms poll: retried on its own change events", n)
	}
	got := readUnderLock(t, r, path)
	if m := parseResolvConf([]byte(got)); !m.managed || string(m.original) == isp {
		t.Fatalf("the file is not cut inside the original:\n%s", got)
	}
	restoredTo(t, path, r, isp)
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
