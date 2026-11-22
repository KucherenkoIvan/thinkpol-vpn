//go:build unix

package lab

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPoolStartGivesWayToALabThatCameBack: a test whose own lab start
// waits for a slot takes a lab that comes back meanwhile, once no test
// waits in take (a waiting test has nothing coming, so it goes first); the
// start then leaves the slot queue, gives the process's share of it back
// and is counted out, so the pool neither waits for that slot nor keeps a
// lab nobody asked for.
func TestPoolStartGivesWayToALabThatCameBack(t *testing.T) {
	dir := oneSlotHost(t)
	queueShareOf(t, 1)
	ctx, cancel := context.WithTimeout(t.Context(), time.Minute)
	defer cancel()
	held := holdSlot(t, ctx)
	timeline := filepath.Join(t.TempDir(), "timeline")
	t.Setenv(TimelineEnv, timeline)
	p := &Pool{size: 2, name: "router", labs: 1} // one lab in use
	far := time.Now().Add(time.Minute)
	inUse := &pooledLab{ops: &fakeLab{project: "lab-in-use"}}
	startErr := make(chan error, 1)
	start := func(ctx context.Context) (*pooledLab, error) {
		release, err := waitForSlot(ctx, labBudget.begin(time.Time{}), "tplab-pool-test", "")
		startErr <- err
		if err != nil {
			return p.adopt(nil, nil, time.Now(), err)
		}
		release()
		return &pooledLab{}, nil
	}
	starting := make(chan *pooledLab, 1)
	go func() {
		pl, own, err := p.acquire(ctx, far, unranked, start)
		if err != nil || own {
			t.Errorf("acquire: own %v, %v: want a lab that came back", own, err)
		}
		starting <- pl
	}()
	waitForTickets(t, dir, 1) // its start waits for the slot
	waiting := make(chan *pooledLab, 1)
	go func() {
		pl, _, err := p.take(far, unranked)
		if err != nil {
			t.Error(err)
		}
		waiting <- pl
	}()
	poolCountIs(t, p, "waiters (the pool is full)", 1, func() int { return len(p.waiters) })
	receive := func(ch chan *pooledLab, who string) *pooledLab {
		t.Helper()
		select {
		case pl := <-ch:
			return pl
		case <-time.After(10 * time.Second):
			t.Fatalf("%s got no lab", who)
			return nil
		}
	}
	p.mu.Lock()
	p.putBack(inUse)
	p.mu.Unlock()
	if pl := receive(waiting, "the waiting test"); pl != inUse {
		t.Fatalf("the waiting test got %v, want the lab that came back", pl)
	}
	select {
	case pl := <-starting:
		t.Fatalf("the starting test got %v while a test waited", pl)
	default:
	}
	p.mu.Lock()
	p.putBack(inUse)
	p.mu.Unlock()
	if pl := receive(starting, "the starting test"); pl != inUse {
		t.Fatalf("the starting test got %v, want the lab that came back", pl)
	}
	select {
	case err := <-startErr:
		if !errors.Is(err, errSlotWaitStopped) {
			t.Fatalf("the start ended with %v, want it to have left the slot queue", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the start no test needs any more still waits for the slot")
	}
	waitForTickets(t, dir, 0)
	p.down.Wait()
	// The timeline shows that the start gave way, and to which lab.
	lines, err := os.ReadFile(timeline)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{" slot-wait ", " gave-way tplab-pool-test\n", " pool-gave-way lab-in-use "} {
		if !strings.Contains(string(lines), want) {
			t.Errorf("the timeline has no %q:\n%s", want, lines)
		}
	}
	p.mu.Lock()
	labs, idle := p.labs, len(p.idle)
	p.mu.Unlock()
	if labs != 1 || idle != 0 {
		t.Errorf("%d labs, %d idle: want 1 and 0, the start no test needed counted out", labs, idle)
	}
	// Its place in the process's share of the slot queue is free: another
	// start joins the queue.
	got := make(chan func(), 1)
	go func() {
		release, err := acquireHostSlot(ctx)
		if err != nil {
			t.Error(err)
		}
		got <- release
	}()
	waitForTickets(t, dir, 1)
	held()
	if release := <-got; release != nil {
		release()
	}
}

// TestAStoppedStartTakesNoFreeSlot: a lab start whose slot wait was
// stopped before it began (its pool's test took a lab that came back)
// takes no slot, not even a free one, whether the process's share of the
// slot queue held it back or not and whether the queue can be used or
// not, so no lab starts that nobody waits for.
func TestAStoppedStartTakesNoFreeSlot(t *testing.T) {
	t.Setenv(TimelineEnv, "") // its start isn't the run's
	for _, c := range []struct {
		share    int
		unusable bool // slot-queue is a file: the wait polls the slots
	}{{0, false}, {1, false}, {0, true}} {
		dir := oneSlotHost(t)
		queueShareOf(t, c.share)
		if c.unusable {
			if err := os.WriteFile(filepath.Join(dir, "slot-queue"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		stop := make(chan struct{})
		close(stop)
		release, err := waitForSlot(withSlotWaitStop(t.Context(), stop), labBudget.begin(time.Time{}), "tplab-stopped", "")
		if release != nil {
			release()
		}
		if !errors.Is(err, errSlotWaitStopped) {
			t.Errorf("%+v: the stopped start's wait ended with %v (a slot: %v), want it to have left", c, err, release != nil)
		}
		if !c.unusable {
			waitForTickets(t, dir, 0)
		}
	}
}
