package lab

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// MaxLabsEnv caps how many slots labs may hold at once across every checkout
// that shares a temporary directory (TMPDIR), i.e. every run of this user on
// the host. The labs one top-level test starts share a slot; a subtest that
// starts its own lab (lab.StartOwnSlot) holds a slot of its own.
const MaxLabsEnv = "THINKPOL_LAB_MAX_LABS"

const defaultMaxLabs = 12

// lockDir holds the host-wide locks: one for allocating subnets (and the
// subnet reservations, see reserveSubnets), one per lab slot and the queue
// of slot waiters (see acquireSlotLock), one for the lab image build, and
// the perf lock.
func lockDir() (string, error) {
	dir := filepath.Join(os.TempDir(), "thinkpol-lab-locks")
	return dir, os.MkdirAll(dir, 0o700)
}

// waitLock takes the first free lock among paths, polling until ctx ends.
func waitLock(ctx context.Context, what string, paths ...string) (release func(), err error) {
	return waitLockMode(ctx, what, true, paths...)
}

// waitLockMode is waitLock for an exclusive or a shared lock.
func waitLockMode(ctx context.Context, what string, exclusive bool, paths ...string) (release func(), err error) {
	release, err = pollLock(ctx, 250*time.Millisecond, exclusive, paths...)
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("lab: waiting for %s: %w", what, err)
		}
		return nil, fmt.Errorf("lab: %s: %w", what, err)
	}
	return release, nil
}

// pollLock tries the paths every interval until it holds one or ctx ends,
// returning ctx's error then. It tries once even if ctx has already ended.
func pollLock(ctx context.Context, every time.Duration, exclusive bool, paths ...string) (release func(), err error) {
	for {
		for _, p := range paths {
			f, ok, err := tryLockMode(p, exclusive)
			if err != nil {
				return nil, err
			}
			if ok {
				return func() { _ = f.Close() }, nil
			}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(every):
		}
	}
}

// Slots held by this process, by key, so a test starting a second lab
// reuses its first lab's slot instead of waiting for one: with every slot
// held by tests waiting for a second, nothing would ever free one.
var (
	slotsMu sync.Mutex
	slots   = map[string]*heldSlot{}
)

type heldSlot struct {
	ready   chan struct{} // closed once the host slot is held, or failed
	err     error
	release func()
	refs    int
}

// acquireSlot holds a lab slot for key, waiting for a free one unless this
// process already holds key's. An empty key always takes a slot of its own.
// The returned func gives the reference back.
func acquireSlot(ctx context.Context, key string) (func(), error) {
	if key == "" {
		return acquireHostSlot(ctx)
	}
	slotsMu.Lock()
	h, ok := slots[key]
	if ok {
		h.refs++
		slotsMu.Unlock()
		<-h.ready
		if h.err != nil {
			return nil, h.err
		}
		return func() { releaseSlot(key, h) }, nil
	}
	h = &heldSlot{ready: make(chan struct{}), refs: 1}
	slots[key] = h
	slotsMu.Unlock()

	h.release, h.err = acquireHostSlot(ctx)
	close(h.ready)
	if h.err != nil {
		slotsMu.Lock()
		delete(slots, key)
		slotsMu.Unlock()
		return nil, h.err
	}
	return func() { releaseSlot(key, h) }, nil
}

func releaseSlot(key string, h *heldSlot) {
	slotsMu.Lock()
	defer slotsMu.Unlock()
	if h.refs--; h.refs == 0 {
		h.release()
		if slots[key] == h {
			delete(slots, key)
		}
	}
}

// PerfEnv, set to 1 in the nodes of a perf run (make lab-perf), turns on
// tests' performance gates.
const PerfEnv = "THINKPOL_LAB_PERF"

// perfHeld is set while this process holds the perf lock: its own labs
// don't wait for it.
var perfHeld atomic.Bool

// AcquirePerfLock waits until no lab of any run sharing this TMPDIR holds a
// slot, then keeps new ones from starting until released: every lab slot
// holds the perf lock shared, a perf run holds it exclusively. Labs this
// process starts meanwhile don't wait for it. Labs started with make lab-up
// hold no slot once labctl has exited, and runs with another TMPDIR aren't
// seen at all.
func AcquirePerfLock(ctx context.Context) (func(), error) {
	dir, err := lockDir()
	if err != nil {
		return nil, err
	}
	release, err := waitLockMode(ctx, "every other lab to finish (a perf run has the host to itself)", true, filepath.Join(dir, "perf.lock"))
	if err != nil {
		return nil, err
	}
	perfHeld.Store(true)
	return func() {
		perfHeld.Store(false)
		release()
	}, nil
}

// slotClass is a slot waiter's rank in the slot queue: a freed slot goes to
// the oldest waiter of the default stream, and to the oldest of the long
// stream only while no default one waits. The default stream runs under a
// time budget and the long one doesn't (lab/README.md, "Streams"), so the
// long stream's labs give way. A waiter outside a stream counts as default.
// slotUntagged is no waiter's class: it is the class of a ticket taken by
// code from before the classes, whose name carries none.
type slotClass int

const (
	slotDefault slotClass = iota
	slotLong
	slotUntagged
)

// streamSlotClass is the slot class of this process's waiters, by its
// stream (Stream). A misspelt stream waits as default: Stream's other
// callers report it.
func streamSlotClass() slotClass {
	if s, err := Stream(); err == nil && s == StreamLong {
		return slotLong
	}
	return slotDefault
}

func acquireHostSlot(ctx context.Context) (func(), error) {
	return acquireHostSlotAs(ctx, streamSlotClass())
}

func acquireHostSlotAs(ctx context.Context, class slotClass) (func(), error) {
	dir, err := lockDir()
	if err != nil {
		return nil, err
	}
	shared := func() {}
	if !perfHeld.Load() {
		if shared, err = waitLockMode(ctx, "a perf run to finish", false, filepath.Join(dir, "perf.lock")); err != nil {
			return nil, err
		}
	}
	release, err := acquireSlotLock(ctx, dir, class)
	if err != nil {
		shared()
		return nil, err
	}
	return func() {
		release()
		shared()
	}, nil
}

func acquireSlotLock(ctx context.Context, dir string, class slotClass) (func(), error) {
	var err error
	n := defaultMaxLabs
	if v := os.Getenv(MaxLabsEnv); v != "" {
		if n, err = strconv.Atoi(v); err != nil || n < 1 {
			return nil, fmt.Errorf("lab: %s=%q: want a positive number", MaxLabsEnv, v)
		}
	}
	paths := make([]string, n)
	for i := range paths {
		paths[i] = filepath.Join(dir, fmt.Sprintf("slot-%d.lock", i))
	}
	const what = "a free lab slot (" + MaxLabsEnv + ")"
	// A queue that can't be used costs fairness, never the slot: the wait
	// falls back to polling the slots, as every waiter did before the queue
	// (and as waitLock, it tries them once with no time left).
	unqueued := func(reason error) (func(), error) {
		if ctx.Err() == nil {
			noteSlotUnqueued(reason)
		}
		return waitLock(ctx, what, paths...)
	}
	q, err := joinSlotQueue(ctx, dir, class)
	if err != nil {
		return unqueued(err)
	}
	defer q.leave()
	tick := time.NewTicker(q.timing.poll)
	defer tick.Stop()
	for {
		head, err := q.atHead(ctx)
		switch {
		case err != nil && ctx.Err() != nil:
			return nil, fmt.Errorf("lab: waiting for %s: %w", what, ctx.Err())
		case err != nil:
			q.leave()
			return unqueued(err)
		case head:
			if hook := slotHeadHook.Load(); hook != nil {
				(*hook)()
			}
			for _, p := range paths {
				f, ok, err := tryLockMode(p, true)
				if err != nil {
					return nil, fmt.Errorf("lab: %s: %w", what, err)
				}
				if ok {
					return func() { _ = f.Close() }, nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("lab: waiting for %s: %w", what, ctx.Err())
		case <-tick.C:
		}
	}
}

// slotQueueTiming is how the slot queue paces itself; tests shorten it.
type slotQueueTiming struct {
	poll      time.Duration // how often a waiter looks at the queue (and a head at the slots)
	heartbeat time.Duration // how often a waiter refreshes its ticket, and a head scans again
	// stale is how long a ticket not refreshed stays in line, and how long a
	// waiter waits for slot-queue.lock before it gives up on the queue.
	stale time.Duration
}

var slotQueueTimes = slotQueueTiming{
	poll:      100 * time.Millisecond,
	heartbeat: time.Second,
	stale:     15 * time.Second,
}

const (
	slotQueueSuffix  = ".wait"
	slotQueueLongTag = "-long" // ends a long-stream ticket's name, before the suffix
	// slotQueueDefaultTag ends a default ticket's name, before the suffix. An
	// untagged ticket is an older run's (slotUntagged).
	slotQueueDefaultTag = "-default"
	slotQueueLockRetry  = 10 * time.Millisecond
)

// slotQueueTag is the tag a ticket of class carries in its name.
func slotQueueTag(class slotClass) string {
	switch class {
	case slotLong:
		return slotQueueLongTag
	case slotDefault:
		return slotQueueDefaultTag
	}
	return ""
}

// slotHeadHook, when set, is called each time a waiter finds itself the
// head, before it tries the slots: tests wait on it.
var slotHeadHook atomic.Pointer[func()]

// slotQueue is one waiter's place in the slot queue: every slot waiter,
// whichever run or process it belongs to, holds a ticket while it waits, a
// file in slot-queue/ named <sequence>-<pid>-<random>-default.wait, or
// <sequence>-<pid>-<random>-long.wait for a long-stream waiter (slotClass),
// and locked (flock) by its waiter. The sequence is one more than the
// highest live ticket's, assigned under slot-queue.lock held exclusively, so
// tickets are numbered in arrival order; scans take slot-queue.lock shared,
// so no scan sees a ticket before its lock. Only the head tries the slot
// locks: a default waiter with no live default ticket older than its own,
// or a long waiter with no live long ticket older than its own and no live
// default ticket at all. Every other waiter watches the ticket in its way
// (the default ticket just ahead of a default one's; the long ticket just
// ahead of a long one's, else the newest default ticket) and looks again
// when that one leaves. So a freed slot goes to the oldest default waiter,
// else to the oldest long one, and a waiter that isn't first costs a lock
// attempt and a stat per poll, not a sweep of every slot. A long head also
// lists the queue every poll for a default ticket that has joined since: a
// default waiter that joins in the moment between that look and the long
// head's slot attempt can still lose that one slot to it. Long waiters
// wait as long as default ones keep coming, from any run: "the default
// stream ends first" holds within one run, not across runs. Nothing ages a
// long waiter forward; its run's LAB_TIMEOUT bounds the wait.
//
// Runs of code from before the classes may share the queue. Their tickets
// are untagged (<sequence>-<pid>-<random>.wait), and their waiters watch the
// nearest older live ticket of any kind, never looking again while it
// lives. Untagged tickets count when numbering a new ticket and are removed
// when dead like any other, but this code orders by tagged tickets only: an
// untagged ticket is in the way of none of its waiters. Reading one as
// default would deadlock: a long head watching an older run's waiter that
// in turn watches it, both refreshing, neither ever trying a slot. As it
// is, no wait goes round: an untagged waiter waits only on older tickets, a
// default waiter only on older default ones, and a long waiter only on
// default ones or older long ones, so nothing leads from a default waiter
// back to a long or an untagged one, and every wait on an older ticket ends
// at the oldest. An older run's waiter thus waits behind every tagged ticket
// older than its own and none newer, and the code here waits behind none of
// its: a newer run's waiters can take slots ahead of it.
//
// Nothing in the queue can hold the slots up for long:
//   - a waiter that dies loses its ticket's lock with its process, and a
//     ticket nobody holds locked is dead: the next scan that meets it
//     removes it;
//   - a live waiter refreshes its ticket's modification time every
//     heartbeat; a ticket not refreshed within the stale limit (a stopped
//     process, a leaked lock, a machine that slept) is skipped as if it
//     weren't there, though left in place. Its waiter may come back: a head
//     scans again every heartbeat, so it goes back behind a ticket ahead of
//     it that is refreshed again, and two heads don't last;
//   - an entry that isn't a ticket (another name, not a regular file) is
//     ignored, and one that can't be opened or locked is skipped with a
//     warning on stderr;
//   - a queue that can't be used at all (slot-queue isn't a directory, a
//     ticket can't be created, the sequence would overflow, slot-queue.lock
//     held for longer than the stale limit by a stopped process) makes the
//     waiter fall back to polling the slots, unordered, with a
//     "slot-wait unqueued" line in the timeline (TimelineEnv).
type slotQueue struct {
	timing    slotQueueTiming
	class     slotClass
	warned    time.Time // when a skipped ticket was last warned of
	dir, lock string    // slot-queue and slot-queue.lock
	seq       uint64
	path      string
	own       *os.File // this waiter's ticket, locked
	ahead     *os.File // the live ticket just ahead of own; nil at the head
	beat      time.Time
	scanned   time.Time
}

// joinSlotQueue takes a ticket of class behind every live one in dir's slot
// queue.
func joinSlotQueue(ctx context.Context, dir string, class slotClass) (*slotQueue, error) {
	q := &slotQueue{timing: slotQueueTimes, class: class, dir: filepath.Join(dir, "slot-queue"), lock: filepath.Join(dir, "slot-queue.lock")}
	if err := os.MkdirAll(q.dir, 0o700); err != nil {
		return nil, err
	}
	unlock, err := q.lockQueue(ctx, true)
	if err != nil {
		return nil, err
	}
	defer unlock()
	last, ahead, err := q.scan(math.MaxUint64, class)
	if err != nil {
		return nil, err
	}
	if last == math.MaxUint64 {
		closeFile(ahead)
		return nil, fmt.Errorf("lab: the slot queue's sequence is used up (%s)", q.dir)
	}
	q.seq, q.ahead = last+1, ahead
	q.beat = time.Now()
	q.scanned = q.beat
	q.path = filepath.Join(q.dir, fmt.Sprintf("%020d-%d-%08x%s%s", q.seq, os.Getpid(), rand.Uint32(), slotQueueTag(class), slotQueueSuffix))
	f, err := os.OpenFile(q.path, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
	if err != nil {
		closeFile(ahead)
		return nil, err
	}
	if ok, err := tryLockFile(f, true); !ok {
		_ = f.Close()
		_ = os.Remove(q.path)
		closeFile(ahead)
		return nil, fmt.Errorf("lab: locking the slot queue ticket %s: %v", q.path, err)
	}
	q.own = f
	return q, nil
}

// slotWanted says whether a lab start of any run that shares the lock
// directory waits for a slot now: a ticket in dir's slot queue refreshed
// within the stale limit. A waiter that fell back to polling the slots
// (unqueued) has no ticket and isn't seen; a queue that can't be read
// counts as wanted.
func slotWanted(dir string, now time.Time) bool {
	entries, err := os.ReadDir(filepath.Join(dir, "slot-queue"))
	if errors.Is(err, fs.ErrNotExist) {
		return false
	}
	if err != nil {
		return true
	}
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), slotQueueSuffix) {
			continue
		}
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() && now.Sub(info.ModTime()) < slotQueueTimes.stale {
			return true
		}
	}
	return false
}

// lockQueue takes slot-queue.lock, giving up after the stale limit: it is
// held only for a scan, so a longer wait means its holder was stopped
// mid-scan, and waiting for it would stop every waiter's heartbeat too.
func (q *slotQueue) lockQueue(ctx context.Context, exclusive bool) (func(), error) {
	lockCtx, cancel := context.WithTimeout(ctx, q.timing.stale)
	defer cancel()
	unlock, err := pollLock(lockCtx, slotQueueLockRetry, exclusive, q.lock)
	if err != nil && ctx.Err() == nil && lockCtx.Err() != nil {
		return nil, fmt.Errorf("lab: %s held for over %v", q.lock, q.timing.stale)
	}
	return unlock, err
}

// atHead reports whether no live ticket is in this waiter's way (see
// slotQueue), looking again once the one it watched has left, died or gone
// stale, every heartbeat while it is the head, and, for a long head, as
// soon as a fresh default ticket shows up. It refreshes the waiter's own
// ticket on the way.
func (q *slotQueue) atHead(ctx context.Context) (bool, error) {
	now := time.Now()
	if now.Sub(q.beat) >= q.timing.heartbeat {
		_ = os.Chtimes(q.path, now, now)
		q.beat = now
	}
	if q.ahead != nil {
		if ticketLive(q.ahead, now, q.timing.stale) {
			return false, nil
		}
		closeFile(q.ahead)
		q.ahead = nil
	} else if now.Sub(q.scanned) < q.timing.heartbeat && (q.class != slotLong || !q.defaultMayWait(now)) {
		return true, nil
	}
	unlock, err := q.lockQueue(ctx, false)
	if err != nil {
		return false, err
	}
	defer unlock()
	_, q.ahead, err = q.scan(q.seq-1, q.class)
	if err == nil && q.ahead == nil && q.class == slotLong {
		_, q.ahead, err = q.scan(math.MaxUint64, slotDefault)
	}
	q.scanned = time.Now()
	return q.ahead == nil, err
}

// defaultMayWait reports whether the queue lists a default ticket refreshed
// within the stale limit, by name and modification time alone: a ticket it
// finds may be a dead waiter's, which the scan that follows clears away. A
// queue that can't be listed counts as one.
func (q *slotQueue) defaultMayWait(now time.Time) bool {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return true
	}
	for _, e := range entries {
		if _, ok := ticketSeq(e.Name()); !ok || ticketClass(e.Name()) != slotDefault {
			continue
		}
		if info, err := e.Info(); err == nil && info.Mode().IsRegular() && now.Sub(info.ModTime()) < q.timing.stale {
			return true
		}
	}
	return false
}

// ticketLive reports whether f, a ticket, is held locked by a waiter that
// refreshed it within stale of now. Finding out may take f's lock: a
// ticket found not live is only closed.
func ticketLive(f *os.File, now time.Time, stale time.Duration) bool {
	if free, err := tryLockFile(f, true); free || err != nil {
		return false
	}
	fi, err := f.Stat()
	return err == nil && now.Sub(fi.ModTime()) < stale
}

// scan looks through the tickets numbered up to upTo, newest first,
// removing the dead ones, until it meets a live one of class that isn't
// stale. It returns the highest sequence held by a live ticket of any class
// (stale or not; 0 with none) and that first fresh ticket, open, or nil if
// there is none.
func (q *slotQueue) scan(upTo uint64, class slotClass) (last uint64, ahead *os.File, err error) {
	entries, err := os.ReadDir(q.dir)
	if err != nil {
		return 0, nil, err
	}
	type ticket struct {
		seq  uint64
		name string
	}
	var tickets []ticket
	for _, e := range entries {
		if seq, ok := ticketSeq(e.Name()); ok && seq <= upTo && e.Type().IsRegular() {
			tickets = append(tickets, ticket{seq, e.Name()})
		}
	}
	slices.SortFunc(tickets, func(a, b ticket) int { return cmp.Compare(b.seq, a.seq) })
	now := time.Now()
	for _, t := range tickets {
		path := filepath.Join(q.dir, t.name)
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) { // gone since ReadDir: its waiter left
				q.warnSkippedTicket(path, err)
			}
			continue
		}
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			_ = f.Close()
			continue
		}
		dead, err := tryLockFile(f, true)
		if err != nil {
			q.warnSkippedTicket(path, err)
			_ = f.Close()
			continue
		}
		if dead {
			if cur, err := os.Stat(path); err == nil && os.SameFile(cur, fi) {
				_ = os.Remove(path)
			}
			_ = f.Close()
			continue
		}
		last = max(last, t.seq)
		if ticketClass(t.name) == class && now.Sub(fi.ModTime()) < q.timing.stale {
			return last, f, nil
		}
		_ = f.Close()
	}
	return last, nil, nil
}

// warnSkippedTicket says a ticket was passed over for an error (EMFILE,
// ENOLCK, …) rather than for being dead or stale: its waiter, maybe live,
// loses its place to this one. A long head that lists such a ticket as a
// fresh default one scans on every poll, so the warning comes at most once
// a heartbeat.
func (q *slotQueue) warnSkippedTicket(path string, err error) {
	if now := time.Now(); now.Sub(q.warned) >= q.timing.heartbeat {
		q.warned = now
		fmt.Fprintf(os.Stderr, "lab: slot queue: skipping ticket %s: %v\n", path, err)
	}
}

// ticketSeq is the sequence a slot queue ticket's name gives.
func ticketSeq(name string) (uint64, bool) {
	seq, rest, ok := strings.Cut(name, "-")
	if !ok || !strings.HasSuffix(rest, slotQueueSuffix) {
		return 0, false
	}
	n, err := strconv.ParseUint(seq, 10, 64)
	return n, err == nil
}

// ticketClass is the class a slot queue ticket's name gives.
func ticketClass(name string) slotClass {
	switch {
	case strings.HasSuffix(name, slotQueueLongTag+slotQueueSuffix):
		return slotLong
	case strings.HasSuffix(name, slotQueueDefaultTag+slotQueueSuffix):
		return slotDefault
	}
	return slotUntagged
}

// leave removes the waiter's ticket, which lets the one behind it move up.
// Calling it again does nothing.
func (q *slotQueue) leave() {
	closeFile(q.ahead)
	q.ahead = nil
	if q.own != nil {
		_ = os.Remove(q.path)
		_ = q.own.Close()
		q.own = nil
	}
}

func closeFile(f *os.File) {
	if f != nil {
		_ = f.Close()
	}
}
