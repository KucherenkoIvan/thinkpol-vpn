package lab

import (
	"cmp"
	"context"
	"fmt"
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

func acquireHostSlot(ctx context.Context) (func(), error) {
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
	release, err := acquireSlotLock(ctx, dir)
	if err != nil {
		shared()
		return nil, err
	}
	return func() {
		release()
		shared()
	}, nil
}

func acquireSlotLock(ctx context.Context, dir string) (func(), error) {
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
	q, err := joinSlotQueue(ctx, dir)
	if err != nil {
		// A queue that can't be used costs fairness, never the slot: the
		// wait falls back to polling the slots, as every waiter did before
		// the queue (and as waitLock, it tries them once with no time left).
		return waitLock(ctx, what, paths...)
	}
	defer q.leave()
	tick := time.NewTicker(slotQueuePoll)
	defer tick.Stop()
	for {
		head, err := q.atHead(ctx)
		switch {
		case err != nil && ctx.Err() != nil:
			return nil, fmt.Errorf("lab: waiting for %s: %w", what, ctx.Err())
		case err != nil:
			q.leave()
			return waitLock(ctx, what, paths...)
		case head:
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

// The slot queue: every slot waiter, whichever run or process it belongs
// to, holds a ticket while it waits, a file in slot-queue/ named
// <sequence>-<pid>-<random>.wait and locked (flock) by its waiter. The
// sequence is one more than the highest live ticket's, assigned under
// slot-queue.lock held exclusively, so tickets are numbered in arrival
// order. Only the head, the waiter with no live ticket older than its own,
// tries the slot locks; every other waiter watches the ticket just ahead of
// its own and looks again when that one leaves. So a freed slot goes to the
// oldest waiter, and a waiter that isn't first costs a lock attempt and a
// stat per poll, not a sweep of every slot.
//
// Nothing in the queue can hold the slots up for long:
//   - a waiter that dies loses its ticket's lock with its process, and a
//     ticket nobody holds locked is dead: the next scan that meets it
//     removes it;
//   - a live waiter refreshes its ticket's modification time every
//     slotQueueHeartbeat; a ticket not refreshed within slotQueueStale (a
//     stopped process, a leaked lock) is skipped as if it weren't there,
//     though left in place;
//   - an entry that isn't a ticket (another name, a directory, a file that
//     can't be opened) is ignored;
//   - a queue that can't be used at all (slot-queue isn't a directory, a
//     ticket can't be created, a sequence would overflow) makes the waiter
//     fall back to polling the slots, unordered.
const (
	slotQueuePoll      = 100 * time.Millisecond
	slotQueueHeartbeat = time.Second
	slotQueueStale     = 15 * time.Second
	slotQueueSuffix    = ".wait"
	// Scans take slot-queue.lock shared, and a ticket is created and locked
	// under it held exclusively, so no scan sees a ticket before its lock.
	slotQueueLockRetry = 10 * time.Millisecond
)

type slotQueue struct {
	dir, lock string // slot-queue and slot-queue.lock
	seq       uint64
	path      string
	own       *os.File // this waiter's ticket, locked
	ahead     *os.File // the live ticket just ahead of own; nil at the head
	beat      time.Time
}

// joinSlotQueue takes a ticket behind every live one in dir's slot queue.
func joinSlotQueue(ctx context.Context, dir string) (*slotQueue, error) {
	q := &slotQueue{dir: filepath.Join(dir, "slot-queue"), lock: filepath.Join(dir, "slot-queue.lock")}
	if err := os.MkdirAll(q.dir, 0o700); err != nil {
		return nil, err
	}
	unlock, err := pollLock(ctx, slotQueueLockRetry, true, q.lock)
	if err != nil {
		return nil, err
	}
	defer unlock()
	last, ahead, err := q.scan(math.MaxUint64)
	if err != nil {
		return nil, err
	}
	if last == math.MaxUint64 {
		closeFile(ahead)
		return nil, fmt.Errorf("lab: the slot queue's sequence is used up (%s)", q.dir)
	}
	q.seq, q.ahead, q.beat = last+1, ahead, time.Now()
	q.path = filepath.Join(q.dir, fmt.Sprintf("%020d-%d-%08x%s", q.seq, os.Getpid(), rand.Uint32(), slotQueueSuffix))
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

// atHead reports whether no live ticket is ahead of this waiter's, looking
// again for the one ahead once the one it watched has left, died or gone
// stale. It refreshes the waiter's own ticket on the way.
func (q *slotQueue) atHead(ctx context.Context) (bool, error) {
	now := time.Now()
	if now.Sub(q.beat) >= slotQueueHeartbeat {
		_ = os.Chtimes(q.path, now, now)
		q.beat = now
	}
	if q.ahead == nil {
		return true, nil
	}
	if ticketLive(q.ahead, now) {
		return false, nil
	}
	closeFile(q.ahead)
	q.ahead = nil
	unlock, err := pollLock(ctx, slotQueueLockRetry, false, q.lock)
	if err != nil {
		return false, err
	}
	defer unlock()
	_, q.ahead, err = q.scan(q.seq)
	return q.ahead == nil, err
}

// ticketLive reports whether f, a ticket, is held locked by a waiter that
// refreshed it within slotQueueStale of now. Finding out may take f's
// lock: a ticket found not live is only closed.
func ticketLive(f *os.File, now time.Time) bool {
	if free, err := tryLockFile(f, true); free || err != nil {
		return false
	}
	fi, err := f.Stat()
	return err == nil && now.Sub(fi.ModTime()) < slotQueueStale
}

// scan looks through the tickets below seq, newest first, removing the
// dead ones, until it meets a live one that isn't stale. It returns the
// highest sequence held by a live ticket (stale or not; 0 with none) and
// that first fresh ticket, open, or nil if there is none.
func (q *slotQueue) scan(below uint64) (last uint64, ahead *os.File, err error) {
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
		if seq, ok := ticketSeq(e.Name()); ok && seq < below {
			tickets = append(tickets, ticket{seq, e.Name()})
		}
	}
	slices.SortFunc(tickets, func(a, b ticket) int { return cmp.Compare(b.seq, a.seq) })
	now := time.Now()
	for _, t := range tickets {
		path := filepath.Join(q.dir, t.name)
		f, err := os.OpenFile(path, os.O_RDWR, 0)
		if err != nil {
			continue
		}
		fi, err := f.Stat()
		if err != nil || !fi.Mode().IsRegular() {
			_ = f.Close()
			continue
		}
		dead, err := tryLockFile(f, true)
		if err != nil {
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
		if now.Sub(fi.ModTime()) < slotQueueStale {
			return last, f, nil
		}
		_ = f.Close()
	}
	return last, nil, nil
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
