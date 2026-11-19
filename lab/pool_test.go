package lab

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestPoolTake: a pool lets tests start labs up to its size, then queues
// them first come first served; a lab given back goes to the first
// waiter, a lab retired lets the first waiter start one, and a waiter
// whose deadline passes gives up with an error, leaving the queue as it
// was.
func TestPoolTake(t *testing.T) {
	p := &Pool{size: 2, name: "router"}
	far := time.Now().Add(time.Minute)
	for i := range 2 {
		if pl, err := p.take(far); pl != nil || err != nil {
			t.Fatalf("take %d: %v, %v: want leave to start one", i, pl, err)
		}
	}
	type got struct {
		pl  *pooledLab
		err error
	}
	wait := func() chan got {
		ch := make(chan got, 1)
		go func() {
			pl, err := p.take(far)
			ch <- got{pl, err}
		}()
		return ch
	}
	waiting := func(n int) {
		t.Helper()
		deadline := time.Now().Add(10 * time.Second)
		for {
			p.mu.Lock()
			w := len(p.waiters)
			p.mu.Unlock()
			if w == n {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%d waiters, want %d", w, n)
			}
			time.Sleep(time.Millisecond)
		}
	}
	first := wait()
	waiting(1)
	second := wait()
	waiting(2)

	back := &pooledLab{uses: 1}
	p.mu.Lock()
	handed := p.handOn(back)
	p.mu.Unlock()
	if g := <-first; !handed || g.pl != back || g.err != nil {
		t.Fatalf("the first waiter got %v, %v, want the lab given back", g.pl, g.err)
	}
	p.gone() // a lab retired: the next waiter starts one
	if g := <-second; g.pl != nil || g.err != nil {
		t.Fatalf("the second waiter got %v, %v, want leave to start one", g.pl, g.err)
	}
	if p.labs != 2 {
		t.Errorf("%d labs counted, want 2", p.labs)
	}

	if _, err := p.take(time.Now().Add(20 * time.Millisecond)); err == nil || !strings.Contains(err.Error(), "no lab came back") {
		t.Errorf("a full pool past the deadline: %v", err)
	}
	if len(p.waiters) != 0 {
		t.Errorf("%d waiters left after the timeout", len(p.waiters))
	}

	idle := &pooledLab{timer: time.NewTimer(time.Hour)}
	p.idle = append(p.idle, idle)
	if pl, err := p.take(far); pl != idle || err != nil {
		t.Errorf("with a lab idle: %v, %v, want it", pl, err)
	}
	if s := p.Stats(); s.Uses != 5 {
		t.Errorf("%d uses, want 5 (the timed-out take isn't one)", s.Uses)
	}
}

// TestNewPool: one pool per topology, a positive size, and no systemd
// node.
func TestNewPool(t *testing.T) {
	defer func(saved []*Pool) {
		poolsMu.Lock()
		pools = saved
		poolsMu.Unlock()
	}(pools)
	// Topologies of this test's own: the lab tests' pools are in the
	// same binary under the lab tag.
	topo := func(node string, systemd bool) Topology {
		return Topology{
			Networks: []Network{{Name: "pool-test"}},
			Nodes:    []NodeSpec{{Name: node, Networks: []string{"pool-test"}, Systemd: systemd}},
		}
	}
	NewPool(topo("pool-test-a", false), 1)
	for name, f := range map[string]func(){
		"the same topology again": func() { NewPool(topo("pool-test-a", false), 2) },
		"size 0":                  func() { NewPool(topo("pool-test-b", false), 0) },
		"systemd":                 func() { NewPool(topo("pool-test-c", true), 1) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: no panic", name)
				}
			}()
			f()
		}()
	}
}

// TestPoolIdle: an idle lab waits as long as its start took, but at
// least 15 s and at most 3 minutes.
func TestPoolIdle(t *testing.T) {
	for took, want := range map[time.Duration]time.Duration{
		time.Second:      15 * time.Second,
		80 * time.Second: 80 * time.Second,
		time.Hour:        3 * time.Minute,
	} {
		if got := poolIdle(took); got != want {
			t.Errorf("poolIdle(%v) = %v, want %v", took, got, want)
		}
	}
}

// TestSlotWanted: a slot is wanted while the slot queue holds a ticket
// refreshed within the stale limit; an old ticket, another file or a
// directory named like a ticket isn't one, and no queue means nobody
// waits.
func TestSlotWanted(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	if slotWanted(dir, now) {
		t.Error("no queue: wanted")
	}
	q := filepath.Join(dir, "slot-queue")
	if err := os.MkdirAll(filepath.Join(q, "00000000000000000001-1-00000000"+slotQueueSuffix), 0o700); err != nil {
		t.Fatal(err)
	}
	ticket := filepath.Join(q, "00000000000000000002-1-00000000"+slotQueueSuffix)
	for _, f := range []string{filepath.Join(q, "notes"), ticket} {
		if err := os.WriteFile(f, nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if !slotWanted(dir, now) {
		t.Error("a fresh ticket: not wanted")
	}
	old := now.Add(-slotQueueTimes.stale - time.Second)
	if err := os.Chtimes(ticket, old, old); err != nil {
		t.Fatal(err)
	}
	if slotWanted(dir, now) {
		t.Error("only a stale ticket, a directory and another file: wanted")
	}
}
