//go:build unix

package lab

import (
	"context"
	"errors"
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
	p := &Pool{size: 2, name: "router"}
	far := time.Now().Add(time.Minute)
	if pl, err := p.take(far, unranked); pl != nil || err != nil {
		t.Fatalf("the first test: %v, %v: want leave to start one", pl, err)
	}
	inUse := &pooledLab{}
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
		pl, err := p.acquire(ctx, far, unranked, start)
		if err != nil {
			t.Error(err)
		}
		starting <- pl
	}()
	waitForTickets(t, dir, 1) // its start waits for the slot
	waiting := make(chan *pooledLab, 1)
	go func() {
		pl, err := p.take(far, unranked)
		if err != nil {
			t.Error(err)
		}
		waiting <- pl
	}()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		p.mu.Lock()
		n := len(p.waiters)
		p.mu.Unlock()
		if n == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d waiters, want 1: the pool is full", n)
		}
	}
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
