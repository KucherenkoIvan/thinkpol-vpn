package lab

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
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
		if pl, starter, err := p.take(far, unranked); pl != nil || starter == nil || err != nil {
			t.Fatalf("take %d: %v, %v: want leave to start one", i, pl, err)
		}
	}
	type got struct {
		pl      *pooledLab
		starter bool
		err     error
	}
	wait := func() chan got {
		ch := make(chan got, 1)
		go func() {
			pl, starter, err := p.take(far, unranked)
			ch <- got{pl, starter != nil, err}
		}()
		return ch
	}
	first := wait()
	poolCountIs(t, p, "waiters", 1, func() int { return len(p.waiters) })
	second := wait()
	poolCountIs(t, p, "waiters", 2, func() int { return len(p.waiters) })

	back := &pooledLab{uses: 1}
	p.mu.Lock()
	handed := p.handOn(back)
	p.mu.Unlock()
	if g := <-first; !handed || g.pl != back || g.err != nil {
		t.Fatalf("the first waiter got %v, %v, want the lab given back", g.pl, g.err)
	}
	p.gone() // a lab retired: the next waiter starts one
	if g := <-second; g.pl != nil || !g.starter || g.err != nil {
		t.Fatalf("the second waiter got %v, %v, want leave to start one", g.pl, g.err)
	}
	if p.labs != 2 {
		t.Errorf("%d labs counted, want 2", p.labs)
	}

	if _, _, err := p.take(time.Now().Add(20*time.Millisecond), unranked); err == nil || !strings.Contains(err.Error(), "no lab came back") {
		t.Errorf("a full pool past the deadline: %v", err)
	}
	if len(p.waiters) != 0 {
		t.Errorf("%d waiters left after the timeout", len(p.waiters))
	}

	idle := &pooledLab{timer: time.NewTimer(time.Hour)}
	p.idle = append(p.idle, idle)
	if pl, starter, err := p.take(far, unranked); pl != idle || starter != nil || err != nil {
		t.Errorf("with a lab idle: %v, %v, want it", pl, err)
	}
}

// poolCountIs waits up to 10 seconds for n, read under p.mu, to be want.
func poolCountIs(t *testing.T, p *Pool, what string, want int, n func() int) {
	t.Helper()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(time.Millisecond) {
		p.mu.Lock()
		got := n()
		p.mu.Unlock()
		if got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d %s, want %d", got, what, want)
		}
	}
}

// TestPoolTakeInOrder: with the pool full, a lab given back goes to the
// waiting test of the lowest rank, those of one rank in the order they
// came, every ranked one before those that wait unranked (Acquire); a lab
// retired lets the next of them start one.
func TestPoolTakeInOrder(t *testing.T) {
	p := &Pool{size: 1, name: "router", labs: 1}
	far := time.Now().Add(time.Minute)
	got := make(chan string, 8)
	for i, w := range []struct {
		name string
		rank int
	}{{"unranked 1", unranked}, {"rank 3", 3}, {"rank 1", 1}, {"unranked 2", unranked}, {"rank 1 again", 1}, {"rank 0", 0}} {
		go func() {
			pl, _, err := p.take(far, w.rank)
			if err != nil {
				got <- w.name + ": " + err.Error()
				return
			}
			got <- fmt.Sprintf("%s: %v", w.name, pl != nil)
		}()
		poolCountIs(t, p, "waiters", i+1, func() int { return len(p.waiters) })
	}
	var order []string
	for i := range 6 {
		p.mu.Lock()
		if i%2 == 0 {
			p.handOn(&pooledLab{})
			p.mu.Unlock()
		} else {
			p.labs--
			p.handOn(nil)
			p.mu.Unlock()
		}
		order = append(order, <-got)
	}
	want := []string{"rank 0: true", "rank 1: false", "rank 1 again: true", "rank 3: false", "unranked 1: true", "unranked 2: false"}
	if !slices.Equal(order, want) {
		t.Errorf("served %q, want %q", order, want)
	}
}

// TestPoolWaitsForLabsComing: while labs started first are coming up, a
// test that finds none idle waits for one of them rather than start a
// lab, as long as more are coming than tests wait; past that it starts
// one, room allowing. A lab that came goes to the first waiter; a start
// that failed lets the next waiter start one instead.
func TestPoolWaitsForLabsComing(t *testing.T) {
	p := &Pool{size: 5, name: "router", labs: 2, coming: 2}
	far := time.Now().Add(time.Minute)
	got := make(chan *pooledLab, 2)
	for i := range 2 {
		go func() {
			pl, _, err := p.take(far, unranked)
			if err != nil {
				t.Error(err)
			}
			got <- pl
		}()
		poolCountIs(t, p, "waiters (a test started a lab while one was coming for it)", i+1, func() int { return len(p.waiters) })
	}
	if pl, _, err := p.take(far, unranked); pl != nil || err != nil {
		t.Fatalf("a third test, with two coming for two waiting: %v, %v, want leave to start one", pl, err)
	}
	up := &pooledLab{}
	p.mu.Lock()
	p.came(up)
	p.mu.Unlock()
	if pl := <-got; pl != up {
		t.Errorf("the first waiter got %v, want the lab that came", pl)
	}
	p.gone() // the start failed: adopt counts it out
	p.mu.Lock()
	p.came(nil)
	p.mu.Unlock()
	if pl := <-got; pl != nil {
		t.Errorf("after a failed start the second waiter got %v, want leave to start one", pl)
	}
	if p.labs != 3 || p.coming != 0 {
		t.Errorf("%d labs, %d coming, want 3 and 0", p.labs, p.coming)
	}
	// A test that came between the failed start's count-out and came
	// waited for the lab coming; came lets it start one.
	p = &Pool{size: 5, name: "router", coming: 1}
	go func() {
		pl, _, err := p.take(far, unranked)
		if err != nil {
			t.Error(err)
		}
		got <- pl
	}()
	poolCountIs(t, p, "waiters", 1, func() int { return len(p.waiters) })
	p.mu.Lock()
	p.came(nil)
	p.mu.Unlock()
	select {
	case pl := <-got:
		if pl != nil {
			t.Errorf("got %v, want leave to start one", pl)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the waiter still waits for a lab no longer coming")
	}
}

// TestPoolTearsDownAStartNobodyNeedsAtClose: a start no test needs any
// more that holds its slot already goes on; when it ends after the pool
// closed, its lab is torn down, and closing waits for it, so no lab
// outlives the run.
func TestPoolTearsDownAStartNobodyNeedsAtClose(t *testing.T) {
	p := &Pool{size: 2, name: "router", labs: 1} // one lab in use
	far := time.Now().Add(time.Minute)
	late := &fakeLab{project: "lab-late"}
	proceed := make(chan struct{})
	got := make(chan *pooledLab, 1)
	go func() {
		pl, _, err := p.acquire(t.Context(), far, unranked, func(context.Context) (*pooledLab, error) {
			<-proceed // it holds its slot: giving up its wait changes nothing
			return &pooledLab{ops: late}, nil
		})
		if err != nil {
			t.Error(err)
		}
		got <- pl
	}()
	poolCountIs(t, p, "tests starting a lab", 1, func() int { return len(p.starters) })
	inUse := &pooledLab{ops: &fakeLab{project: "lab-in-use"}}
	p.mu.Lock()
	p.putBack(inUse)
	p.mu.Unlock()
	if pl := <-got; pl != inUse {
		t.Fatalf("the starting test got %v, want the lab that came back", pl)
	}
	closed := make(chan error, 1)
	go func() {
		var stats strings.Builder
		closed <- p.close(&stats, "tests")
	}()
	select {
	case err := <-closed:
		t.Fatalf("the pool closed (%v) while a lab of its was still starting", err)
	case <-time.After(200 * time.Millisecond):
	}
	close(proceed)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
	if c := late.counts(); c[3] != 1 {
		t.Errorf("the late lab was torn down %d times, want once", c[3])
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.labs != 1 || len(p.idle) != 0 {
		t.Errorf("%d labs, %d idle: want the one in use only", p.labs, len(p.idle))
	}
}

// TestPoolStarterGetsALabBeforeItsStartBegins: a test is a starter from
// the moment the pool counts its start in, whether take let it start one
// or a lab that went let it, while it waited, start one: a lab that comes
// back before its start began goes to it, not idle.
func TestPoolStarterGetsALabBeforeItsStartBegins(t *testing.T) {
	far := time.Now().Add(time.Minute)
	got := func(starter chan *pooledLab, want *pooledLab, what string) {
		t.Helper()
		select {
		case pl := <-starter:
			if pl != want {
				t.Errorf("%s: the starter got %v, want the lab that came back", what, pl)
			}
		default:
			t.Errorf("%s: the lab that came back didn't go to the starter", what)
		}
	}
	p := &Pool{size: 1, name: "router"}
	_, starter, err := p.take(far, unranked)
	if starter == nil || err != nil {
		t.Fatalf("take: starter %v, %v: want leave to start one", starter != nil, err)
	}
	back := &pooledLab{timer: time.NewTimer(time.Hour)}
	p.mu.Lock()
	p.putBack(back)
	p.mu.Unlock()
	got(starter, back, "left to start one")

	p = &Pool{size: 2, name: "router", labs: 2} // both in use
	took := make(chan chan *pooledLab, 1)
	go func() {
		_, starter, err := p.take(far, unranked)
		if err != nil {
			t.Error(err)
		}
		took <- starter
	}()
	poolCountIs(t, p, "waiters", 1, func() int { return len(p.waiters) })
	p.gone() // one retired: the waiting test starts one
	p.mu.Lock()
	p.putBack(back) // the other came back
	p.mu.Unlock()
	if starter = <-took; starter == nil {
		t.Fatal("the waiting test got no start after a lab went")
	}
	got(starter, back, "a waiter let start one")
}

// TestPoolKeepsAStartNobodyNeedsForTheNextTest: a start no test needs any
// more that holds its slot already goes on; when it ends with the pool
// open, its lab joins the pool, idle, and the next test takes it instead
// of starting one.
func TestPoolKeepsAStartNobodyNeedsForTheNextTest(t *testing.T) {
	p := &Pool{size: 2, name: "router", labs: 1} // one lab in use
	far := time.Now().Add(time.Minute)
	late := &pooledLab{ops: &fakeLab{project: "lab-late"}, timer: time.NewTimer(time.Hour)}
	proceed := make(chan struct{})
	got := make(chan *pooledLab, 1)
	go func() {
		pl, own, err := p.acquire(t.Context(), far, unranked, func(context.Context) (*pooledLab, error) {
			<-proceed // it holds its slot: giving up its wait changes nothing
			return late, nil
		})
		if err != nil || own {
			t.Errorf("acquire: own %v, %v: want a lab that came back", own, err)
		}
		got <- pl
	}()
	poolCountIs(t, p, "tests starting a lab", 1, func() int { return len(p.starters) })
	inUse := &pooledLab{ops: &fakeLab{project: "lab-in-use"}}
	p.mu.Lock()
	p.putBack(inUse)
	p.mu.Unlock()
	if pl := <-got; pl != inUse {
		t.Fatalf("the starting test got %v, want the lab that came back", pl)
	}
	close(proceed)
	p.down.Wait()
	p.mu.Lock()
	labs, idle := p.labs, slices.Clone(p.idle)
	p.mu.Unlock()
	if labs != 2 || !slices.Equal(idle, []*pooledLab{late}) {
		t.Fatalf("%d labs, idle %v: want 2, the late start's lab idle", labs, idle)
	}
	if pl, starter, err := p.take(far, unranked); pl != late || starter != nil || err != nil {
		t.Errorf("the next test: %v, starter %v, %v: want the late start's lab", pl, starter != nil, err)
	}
}

// TestNewPool: one pool per topology, a positive size, and no systemd
// or privileged node.
func TestNewPool(t *testing.T) {
	defer func(saved []*Pool) {
		poolsMu.Lock()
		pools = saved
		poolsMu.Unlock()
	}(pools)
	// Topologies of this test's own: the lab tests' pools are in the
	// same binary under the lab tag.
	topo := func(node string, systemd, privileged bool) Topology {
		return Topology{
			Networks: []Network{{Name: "pool-test"}},
			Nodes:    []NodeSpec{{Name: node, Networks: []string{"pool-test"}, Systemd: systemd, Privileged: privileged}},
		}
	}
	NewPool(topo("pool-test-a", false, false), 1)
	for name, f := range map[string]func(){
		"the same topology again": func() { NewPool(topo("pool-test-a", false, false), 2) },
		"size 0":                  func() { NewPool(topo("pool-test-b", false, false), 0) },
		"systemd":                 func() { NewPool(topo("pool-test-c", true, false), 1) },
		"privileged":              func() { NewPool(topo("pool-test-d", false, true), 1) },
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

// fakeLab stands in for a started lab (pooledOps), counting what the pool
// did to it.
type fakeLab struct {
	project  string
	resetErr error
	keepEnv  bool
	undone   string // what its reset logs as undone
	downErr  error

	mu                             sync.Mutex
	resets, cleanups, kept, downed int
}

func (f *fakeLab) name() string { return f.project }

func (f *fakeLab) reset(_ context.Context, _ *Snapshot, logf func(format string, args ...any)) error {
	f.mu.Lock()
	f.resets++
	f.mu.Unlock()
	if f.undone != "" {
		logf("device-a: the reset undid what was left behind:%s", f.undone)
	}
	return f.resetErr
}

func (f *fakeLab) cleanup(labUser, time.Time) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cleanups++
}

func (f *fakeLab) keep(labUser) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.keepEnv {
		f.kept++
	}
	return f.keepEnv
}

func (f *fakeLab) down(context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.downed++
	return f.downErr
}

func (f *fakeLab) counts() [4]int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return [4]int{f.resets, f.cleanups, f.kept, f.downed}
}

// fakeTB is a test that ended, failed or not, as giveBack sees it.
type fakeTB struct {
	testing.TB
	name   string
	failed bool
	mu     sync.Mutex
	logs   []string
}

func (f *fakeTB) Name() string { return f.name }
func (f *fakeTB) Failed() bool { return f.failed }
func (f *fakeTB) Helper()      {}

func (f *fakeTB) Logf(format string, args ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logs = append(f.logs, fmt.Sprintf(format, args...))
}

func (f *fakeTB) Errorf(format string, args ...any) {
	f.failed = true
	f.Logf(format, args...)
}

func (f *fakeTB) log() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.logs, "\n")
}

// TestPoolGiveBack: a failed test's lab is retired (torn down or kept by
// its clean-up) without a reset; a lab whose reset didn't hold is retired
// and torn down, or kept with KeepEnv; a lab whose reset held goes to the
// first waiter, or idle. What a reset undid is logged after the tests
// that had the lab before.
func TestPoolGiveBack(t *testing.T) {
	t.Setenv(TimelineEnv, "") // its labs aren't the run's
	retiredFor := func(p *Pool, test, why string) bool {
		s := p.Stats()
		return len(s.Retired) == 1 && s.Retired[0] == test+" ("+why+")"
	}

	p := &Pool{size: 1, name: "router", labs: 1}
	f := &fakeLab{project: "lab-1"}
	p.giveBack(&fakeTB{name: "TestFailed", failed: true}, &pooledLab{ops: f}, time.Now())
	if c := f.counts(); c != [4]int{0, 1, 0, 0} || p.labs != 0 || len(p.idle) != 0 || !retiredFor(p, "TestFailed", "it failed") {
		t.Errorf("a failed test: resets, cleanups, kept, downs %v, %d labs, %d idle, retired %q: want its clean-up only, retired", c, p.labs, len(p.idle), p.Stats().Retired)
	}

	for _, keepEnv := range []bool{false, true} {
		p := &Pool{size: 1, name: "router", labs: 1}
		f := &fakeLab{project: "lab-1", resetErr: errors.New("device-a: left behind: qdisc"), keepEnv: keepEnv}
		tb := &fakeTB{name: "TestLeaky"}
		p.giveBack(tb, &pooledLab{ops: f}, time.Now())
		want := [4]int{1, 0, 0, 1}
		if keepEnv {
			want = [4]int{1, 0, 1, 0}
		}
		if c := f.counts(); c != want || p.labs != 0 || len(p.idle) != 0 || !retiredFor(p, "TestLeaky", "its reset didn't hold") || tb.failed {
			t.Errorf("a reset that didn't hold (keep %v): resets, cleanups, kept, downs %v, want %v; %d labs, %d idle, retired %q, test failed %v",
				keepEnv, c, want, p.labs, len(p.idle), p.Stats().Retired, tb.failed)
		}
		if !strings.Contains(tb.log(), "qdisc") {
			t.Errorf("a reset that didn't hold: the log doesn't say why: %s", tb.log())
		}
	}

	p = &Pool{size: 1, name: "router", labs: 1}
	f = &fakeLab{project: "lab-1", undone: "\n  process 90 thinkpol up"}
	pl := &pooledLab{ops: f, users: []string{"TestA", "TestB"}}
	tb := &fakeTB{name: "TestC"}
	p.giveBack(tb, pl, time.Now())
	if len(p.idle) != 1 || p.idle[0] != pl || p.labs != 1 || len(p.Stats().Retired) != 0 {
		t.Fatalf("a reset that held: %d idle, %d labs, retired %q: want it idle", len(p.idle), p.labs, p.Stats().Retired)
	}
	p.idle[0].timer.Stop()
	if log := tb.log(); !strings.Contains(log, "before it: TestA, TestB\n") || !strings.Contains(log, "process 90 thinkpol up") {
		t.Errorf("what the reset undid isn't logged after the tests before: %s", log)
	}
	if !slices.Equal(pl.users, []string{"TestA", "TestB", "TestC"}) {
		t.Errorf("users %q", pl.users)
	}

	p.idle = nil
	ch := make(chan *pooledLab, 1)
	p.waiters = []poolWaiter{{ch: ch, rank: unranked}}
	p.giveBack(&fakeTB{name: "TestD"}, pl, time.Now())
	if len(ch) != 1 || len(p.idle) != 0 || len(p.waiters) != 0 {
		t.Errorf("with a waiter: %d handed on, %d idle: want the lab handed on", len(ch), len(p.idle))
	} else if got := <-ch; got != pl {
		t.Errorf("with a waiter: it got %v, want the lab", got)
	}
}

// TestPoolIdleCheck: an idle lab stays while it hasn't waited as long as
// its start took, or while no lab start wants a slot (up to poolIdleMax);
// past that it is torn down and the first waiter may start one; a lab
// taken meanwhile is left alone.
func TestPoolIdleCheck(t *testing.T) {
	t.Setenv(TimelineEnv, "") // its labs aren't the run's
	for _, c := range []struct {
		what   string
		wanted bool
		idle   time.Duration
		goes   bool
	}{
		{"a slot wanted, idle as long as its start", true, poolIdle(0) + time.Second, true},
		{"a slot wanted, idle shorter than its start", true, poolIdle(0) - 5*time.Second, false},
		{"no slot wanted", false, poolIdle(0) + time.Second, false},
		{"no slot wanted, idle past the most", false, poolIdleMax + time.Second, true},
	} {
		p := &Pool{size: 1, name: "router", labs: 1, slotWanted: func() bool { return c.wanted }}
		f := &fakeLab{project: "lab-1"}
		pl := &pooledLab{ops: f, since: time.Now().Add(-c.idle), timer: time.NewTimer(time.Hour)}
		p.idle = []*pooledLab{pl}
		ch := make(chan *pooledLab, 1)
		p.waiters = []poolWaiter{{ch: ch, rank: unranked}}
		p.idleCheck(pl)
		p.down.Wait()
		p.mu.Lock()
		idle, labs := len(p.idle), p.labs
		p.mu.Unlock()
		if c.goes {
			if len(ch) != 1 || idle != 0 || labs != 1 || f.counts()[3] != 1 {
				t.Errorf("%s: %d handed to the waiter, %d idle, %d labs, %d downs: want torn down, the waiter to start one", c.what, len(ch), idle, labs, f.counts()[3])
			} else if got := <-ch; got != nil {
				t.Errorf("%s: the waiter got %v, want to start one", c.what, got)
			}
			continue
		}
		pl.timer.Stop()
		if idle != 1 || labs != 1 || len(ch) != 0 || f.counts()[3] != 0 {
			t.Errorf("%s: %d idle, %d labs, %d downs: want it idle", c.what, idle, labs, f.counts()[3])
		}
	}

	p := &Pool{size: 1, name: "router", labs: 1, slotWanted: func() bool { return true }}
	f := &fakeLab{project: "lab-1"}
	p.idleCheck(&pooledLab{ops: f, since: time.Now().Add(-time.Hour)})
	if p.labs != 1 || f.counts()[3] != 0 {
		t.Errorf("a lab taken meanwhile: %d labs, %d downs: want it left alone", p.labs, f.counts()[3])
	}
}

// TestClosePools: closing tears down every pool's idle labs, refuses
// takes after, and writes each used pool's starts, uses and retirements.
func TestClosePools(t *testing.T) {
	t.Setenv(TimelineEnv, "") // its labs aren't the run's
	defer func(saved []*Pool) {
		poolsMu.Lock()
		pools = saved
		poolsMu.Unlock()
	}(pools)
	used := &Pool{size: 2, name: "router,device-a", labs: 2, stats: PoolStats{Started: 2, Uses: 5, Retired: []string{"TestX (its reset didn't hold)"}}}
	a, b := &fakeLab{project: "lab-1"}, &fakeLab{project: "lab-2"}
	used.idle = []*pooledLab{{ops: a, timer: time.NewTimer(time.Hour)}, {ops: b, timer: time.NewTimer(time.Hour)}}
	unused := &Pool{size: 1, name: "router"}
	poolsMu.Lock()
	pools = []*Pool{used, unused}
	poolsMu.Unlock()

	var out strings.Builder
	closePools(&out)
	if a.counts()[3] != 1 || b.counts()[3] != 1 || len(used.idle) != 0 || used.labs != 0 {
		t.Errorf("downs %d, %d, %d idle, %d labs: want both idle labs torn down", a.counts()[3], b.counts()[3], len(used.idle), used.labs)
	}
	want := "lab pool router,device-a: 2 labs started for 5 tests, 1 retired\nlab pool router,device-a: retired after TestX (its reset didn't hold)\n"
	if out.String() != want {
		t.Errorf("closePools wrote %q, want %q", out.String(), want)
	}
	if _, _, err := unused.take(time.Now().Add(time.Minute), unranked); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Errorf("a take after closing: %v, want closed", err)
	}
}
