package lab

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// Pool keeps started labs of one topology for the tests that use it, one
// test after another per lab: a lab start costs a minute or more on a busy
// Docker, and most tests hold their lab for seconds to a minute. A test
// takes a lab (Acquire); when it ends, the lab is reset to the state it
// came up in (Lab.Reset) and goes to the next test only if the check
// passed. A lab whose check failed, or whose test failed, is retired: torn
// down (or kept, with KeepEnv), the next test getting a fresh one. A test
// that needs a fresh lab calls Start instead.
//
// A pool holds at most size labs, each with a lab slot of its own for as
// long as it lives: a test that finds none idle starts one while the pool
// has fewer, or waits for one to come back, first come first served. An
// idle lab stays while no lab start waits for a slot, since the slot it
// holds then costs nobody anything; once one waits, the idle lab goes when
// it has waited as long as its start took (poolIdle). Main tears down what
// the pools still hold.
type Pool struct {
	topo Topology
	size int
	name string

	mu      sync.Mutex
	idle    []*pooledLab
	labs    int               // started or starting, idle or in use
	waiters []chan *pooledLab // first come first served; a nil lab: start one
	stats   PoolStats
	down    sync.WaitGroup // idle labs being torn down
	closed  bool
}

// PoolStats counts what a pool did.
type PoolStats struct {
	Started int      // labs it started
	Uses    int      // tests that took a lab
	Retired []string // the tests whose lab didn't go back, and why
}

type pooledLab struct {
	lab   *Lab
	bins  *runBinaries
	keep  bool
	clean *Snapshot
	uses  int
	took  time.Duration // its start, the slot wait included
	timer *time.Timer   // while idle: the next idle check
	since time.Time     // idle since
}

// poolIdle is how long an idle lab waits for its next test while another
// lab start waits for a slot: as long as its own start took (the slot wait
// included), within bounds. Waiting longer would cost the slot more than a
// new start costs the next test; tearing it down sooner throws away a
// start the next test of the topology, a minute or two behind under load,
// would have used.
func poolIdle(started time.Duration) time.Duration {
	return min(max(started, 15*time.Second), 3*time.Minute)
}

// poolIdleCheck is how often an idle lab looks whether a slot is wanted;
// poolIdleMax is how long it stays idle when none ever is.
const (
	poolIdleCheck = 2 * time.Second
	poolIdleMax   = 10 * time.Minute
)

var (
	poolsMu sync.Mutex
	pools   []*Pool
)

// NewPool makes the process's pool of up to size labs of topo, one per
// topology. A topology with a systemd node can't be pooled: units, their
// enablement and a node's restart are outside what Reset checks.
func NewPool(topo Topology, size int) *Pool {
	if size < 1 {
		panic(fmt.Sprintf("lab: NewPool: size %d", size))
	}
	if err := topo.Validate(); err != nil {
		panic(fmt.Sprintf("lab: NewPool: %v", err))
	}
	var names []string
	for _, n := range topo.Nodes {
		if n.Systemd {
			panic(fmt.Sprintf("lab: NewPool: %s runs systemd, which a reset can't check: start its lab with Start", n.Name))
		}
		names = append(names, n.Name)
	}
	p := &Pool{topo: topo, size: size, name: strings.Join(names, ",")}
	poolsMu.Lock()
	defer poolsMu.Unlock()
	for _, other := range pools {
		if reflect.DeepEqual(other.topo, topo) {
			panic(fmt.Sprintf("lab: NewPool: a pool of %s exists", p.name))
		}
	}
	pools = append(pools, p)
	return p
}

// Acquire gives the test a lab of the pool's topology, which goes back to
// the pool when the test ends (its clean-up, registered here, runs after
// those the test registers later). A test calls it before it registers
// anything that uses the lab.
func (p *Pool) Acquire(t testing.TB) *Lab {
	t.Helper()
	asked := time.Now()
	dl, _ := labBudget.begin(testDeadline(t)).deadline(phaseSlotWait)
	pl, err := p.take(dl)
	if err != nil {
		t.Fatal(err)
	}
	if pl == nil {
		if pl, err = p.start(t); err != nil {
			t.Fatal(err)
		}
	}
	pl.uses++
	since := time.Now()
	t.Cleanup(func() { p.giveBack(t, pl, since) })
	notePool("take", pl.lab.Project, fmt.Sprintf("use %d %s", pl.uses, t.Name()))
	t.Logf("lab %s (pool %s, use %d) after %v", pl.lab.Project, p.name, pl.uses, since.Sub(asked).Round(100*time.Millisecond))
	return pl.lab
}

// take is an idle lab, or nil for the caller to start one, waiting until
// deadline for one to come back when the pool is full.
func (p *Pool) take(deadline time.Time) (*pooledLab, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, fmt.Errorf("lab: pool %s: closed", p.name)
	}
	p.stats.Uses++
	if n := len(p.idle); n > 0 {
		pl := p.idle[n-1]
		p.idle = p.idle[:n-1]
		pl.timer.Stop() // one that fired finds pl taken (idleCheck)
		p.mu.Unlock()
		return pl, nil
	}
	if p.labs < p.size && len(p.waiters) == 0 {
		p.labs++
		p.mu.Unlock()
		return nil, nil
	}
	ch := make(chan *pooledLab, 1)
	p.waiters = append(p.waiters, ch)
	p.mu.Unlock()
	from := time.Now()
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case pl := <-ch:
		return pl, nil
	case <-timer.C:
	}
	p.mu.Lock()
	if i := slices.Index(p.waiters, ch); i >= 0 {
		p.waiters = slices.Delete(p.waiters, i, i+1)
		p.stats.Uses--
		p.mu.Unlock()
		return nil, fmt.Errorf("lab: pool %s: no lab came back within %v", p.name, time.Since(from).Round(time.Second))
	}
	p.mu.Unlock()
	return <-ch, nil // handed on meanwhile
}

// start brings up a lab for the pool, which the caller counted in
// p.labs, and snapshots its clean state.
func (p *Pool) start(t testing.TB) (*pooledLab, error) {
	begin := time.Now()
	l, bins, keep, err := launch(t, p.topo, func(project string) string { return "pool:" + project }, "pool-"+p.name, os.Getenv(ProjectEnv))
	var clean *Snapshot
	if err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		clean, err = l.Snapshot(ctx)
		cancel()
	}
	if err != nil {
		if l != nil {
			ctx, cancel := context.WithTimeout(context.Background(), labBudget.teardown)
			err = errors.Join(err, l.Down(ctx))
			cancel()
		}
		p.gone()
		return nil, err
	}
	p.mu.Lock()
	p.stats.Started++
	p.mu.Unlock()
	return &pooledLab{lab: l, bins: bins, keep: keep, clean: clean, took: time.Since(begin)}, nil
}

// giveBack resets the test's lab and puts it back, or retires it when the
// test failed or the reset didn't hold.
func (p *Pool) giveBack(t testing.TB, pl *pooledLab, since time.Time) {
	if t.Failed() {
		p.retire(t, pl, "the test failed")
		pl.lab.cleanup(t, pl.bins, pl.keep, since)
		p.gone()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	err := pl.lab.Reset(ctx, pl.clean, t.Logf)
	cancel()
	if err != nil {
		t.Logf("lab %s: the reset after this test didn't hold, so the lab goes: %v", pl.lab.Project, err)
		p.retire(t, pl, "its reset didn't hold")
		ctx, cancel := context.WithTimeout(context.Background(), labBudget.teardown)
		if err := pl.lab.Down(ctx); err != nil {
			t.Errorf("lab %s: tear down: %v", pl.lab.Project, err)
		}
		cancel()
		p.gone()
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.handOn(pl) {
		return
	}
	pl.since = time.Now()
	pl.timer = time.AfterFunc(poolIdleCheck, func() { p.idleCheck(pl) })
	p.idle = append(p.idle, pl)
}

func (p *Pool) retire(t testing.TB, pl *pooledLab, why string) {
	notePool("retire", pl.lab.Project, fmt.Sprintf("%s: %s", t.Name(), why))
	p.mu.Lock()
	p.stats.Retired = append(p.stats.Retired, fmt.Sprintf("%s (%s)", t.Name(), why))
	p.mu.Unlock()
}

// gone counts a lab out of the pool, which lets the first waiter start
// one.
func (p *Pool) gone() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.labs--
	p.handOn(nil)
}

// handOn gives pl (nil: leave to start one) to the first waiter, if any.
// p.mu is held.
func (p *Pool) handOn(pl *pooledLab) bool {
	if len(p.waiters) == 0 {
		return false
	}
	ch := p.waiters[0]
	p.waiters = p.waiters[1:]
	if pl == nil {
		p.labs++
	}
	ch <- pl
	return true
}

// idleCheck tears down pl if it is still idle and has been for long
// enough (poolIdle, poolIdleMax), or looks again later.
func (p *Pool) idleCheck(pl *pooledLab) {
	wanted := true
	if dir, err := lockDir(); err == nil {
		wanted = slotWanted(dir, time.Now())
	}
	p.mu.Lock()
	i := slices.Index(p.idle, pl)
	if i < 0 {
		p.mu.Unlock()
		return
	}
	if idle := time.Since(pl.since); idle < poolIdle(pl.took) || !wanted && idle < poolIdleMax {
		pl.timer = time.AfterFunc(poolIdleCheck, func() { p.idleCheck(pl) })
		p.mu.Unlock()
		return
	}
	p.idle = slices.Delete(p.idle, i, i+1)
	p.labs--
	p.handOn(nil)
	p.down.Add(1)
	p.mu.Unlock()
	go func() {
		defer p.down.Done()
		p.teardown(pl, "idle")
	}()
}

func (p *Pool) teardown(pl *pooledLab, why string) {
	notePool("down", pl.lab.Project, fmt.Sprintf("%s after %d uses", why, pl.uses))
	ctx, cancel := context.WithTimeout(context.Background(), labBudget.teardown)
	defer cancel()
	if err := pl.lab.Down(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "lab %s: tear down: %v\n", pl.lab.Project, err)
	}
}

// Stats is what the pool did so far.
func (p *Pool) Stats() PoolStats {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.stats
	s.Retired = slices.Clone(s.Retired)
	return s
}

// closePools tears down every pool's idle labs, waits for those already
// going, and writes each used pool's stats to w.
func closePools(w io.Writer) {
	poolsMu.Lock()
	all := slices.Clone(pools)
	poolsMu.Unlock()
	var wg sync.WaitGroup
	for _, p := range all {
		p.mu.Lock()
		p.closed = true
		idle := p.idle
		p.idle = nil
		p.labs -= len(idle)
		for _, pl := range idle {
			pl.timer.Stop()
			wg.Go(func() { p.teardown(pl, "end of the run") })
		}
		p.mu.Unlock()
	}
	wg.Wait()
	for _, p := range all {
		p.down.Wait()
		if s := p.Stats(); s.Uses > 0 {
			_, _ = fmt.Fprintf(w, "lab pool %s: %d labs started for %d tests, %d retired\n", p.name, s.Started, s.Uses, len(s.Retired))
			for _, r := range s.Retired {
				_, _ = fmt.Fprintf(w, "lab pool %s: retired after %s\n", p.name, r)
			}
		}
	}
}
