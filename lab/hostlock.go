package lab

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
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

// lockDir holds the host-wide locks: one for allocating subnets, one per lab
// slot, and the perf lock.
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
			return nil, fmt.Errorf("lab: waiting for %s: %w", what, ctx.Err())
		case <-time.After(250 * time.Millisecond):
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
	return waitLock(ctx, "a free lab slot ("+MaxLabsEnv+")", paths...)
}

// lockAllocation serializes choosing subnets and creating networks, host-wide.
func lockAllocation(ctx context.Context) (func(), error) {
	dir, err := lockDir()
	if err != nil {
		return nil, err
	}
	return waitLock(ctx, "the subnet allocation lock", filepath.Join(dir, "subnets.lock"))
}
