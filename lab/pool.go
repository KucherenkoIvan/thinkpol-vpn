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
// has fewer, or waits for one to come back, first come first served
// (AcquireInOrder: by rank), taking one that comes back while its own
// start still waits for a slot (startOrTake). An
// idle lab stays while no lab start waits for a slot, since the slot it
// holds then costs nobody anything; once one waits, the idle lab goes when
// it has waited as long as its start took (poolIdle). A pool whose users
// are counted up front (the node phase's packages: countTakers) keeps no
// more labs idle than users may still take one: the slot a surplus lab
// holds is what lab starts elsewhere wait for. Main tears down what the
// pools still hold.
type Pool struct {
	topo Topology
	size int
	name string

	mu       sync.Mutex
	idle     []*pooledLab
	labs     int          // started or starting, idle or in use
	coming   int          // of those, started first (StartFirst) and not up yet
	waiters  []poolWaiter // by rank, then first come first served
	starters []poolWaiter // tests whose own start is on its way, the same order
	stats    PoolStats
	down     sync.WaitGroup // idle labs being torn down, starts no test waits for
	closed   bool
	// takersKnown: takers counts the users that may still take a lab
	// (countTakers); without it, the pool can't tell.
	takers      int
	takersKnown bool
	downErrs    []error // tear-downs of idle labs that failed

	// slotWanted says whether a lab start waits for a slot; nil: one of
	// any run sharing the lock directory (slotWanted).
	slotWanted func() bool
}

// PoolStats counts what a pool did.
type PoolStats struct {
	Started int      // labs it started
	Uses    int      // tests that took a lab
	Retired []string // the tests whose lab didn't go back, and why
}

type pooledLab struct {
	lab   *Lab // what Acquire gives the test
	ops   pooledOps
	clean *Snapshot
	uses  int
	users []string      // the tests that had it, in turn
	took  time.Duration // its start, the slot wait included
	timer *time.Timer   // while idle: the next idle check
	since time.Time     // idle since
}

// poolWaiter is a test waiting for a lab: its channel gets one (a nil
// lab: start one); rank orders it among the waiting (AcquireInOrder).
type poolWaiter struct {
	ch   chan *pooledLab
	rank int
}

// unranked is Acquire's rank: after every test that waits with one.
const unranked = int(^uint(0) >> 1)

// labUser is who had a pool's lab: a test (testing.TB), or a node-phase
// package (packageUser).
type labUser interface {
	Name() string
	Failed() bool
	Logf(format string, args ...any)
	Errorf(format string, args ...any)
}

// pooledOps is what a pool does to one of its labs: a lab test pool's
// (startedLab), the node phase's (nodeLab), or a unit test's stand-in.
type pooledOps interface {
	name() string
	reset(ctx context.Context, clean *Snapshot, logf func(format string, args ...any)) error
	// cleanup, after a failed user, tears the lab down or keeps it
	// (KeepEnv), the containers' logs since since in the user's log.
	cleanup(u labUser, since time.Time)
	// keep keeps the lab up when KeepEnv is set, and says whether it did.
	keep(u labUser) bool
	down(ctx context.Context) error
}

// startedLab is a lab a pool started, with the run's binaries it mounts.
type startedLab struct {
	lab     *Lab
	bins    *runBinaries
	keepEnv bool
}

func (s startedLab) name() string { return s.lab.Project }

func (s startedLab) reset(ctx context.Context, clean *Snapshot, logf func(format string, args ...any)) error {
	return s.lab.Reset(ctx, clean, logf)
}

func (s startedLab) cleanup(u labUser, since time.Time) {
	s.lab.cleanup(u, s.bins, s.keepEnv, since)
}

func (s startedLab) keep(u labUser) bool {
	return s.keepEnv && s.lab.keepRunning(u, s.bins)
}

func (s startedLab) down(ctx context.Context) error { return s.lab.Down(ctx) }

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
// topology. A topology with a systemd node or a privileged one can't be
// pooled: units, their enablement and a node's restart, and what a
// privileged container may change (devices, kernel state beyond its
// namespaces), are outside what Reset checks.
func NewPool(topo Topology, size int) *Pool {
	p := newPool(topo, size)
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

// newPool is NewPool's pool, which Main doesn't know of: its owner closes
// it (close).
func newPool(topo Topology, size int) *Pool {
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
		if n.Privileged {
			panic(fmt.Sprintf("lab: NewPool: %s is privileged, which a reset can't check: start its lab with Start", n.Name))
		}
		names = append(names, n.Name)
	}
	return &Pool{topo: topo, size: size, name: strings.Join(names, ",")}
}

// Acquire gives the test a lab of the pool's topology, which goes back to
// the pool when the test ends (its clean-up, registered here, runs after
// those the test registers later). A test calls it before it registers
// anything that uses the lab.
func (p *Pool) Acquire(t testing.TB) *Lab {
	t.Helper()
	return p.acquireFor(t, unranked)
}

// AcquireInOrder is Acquire for a test that waits its turn by rank: when
// no lab is idle, the lab that comes back (or the start the pool can make)
// goes to the waiting test of the lowest rank, those of one rank first
// come first served, all of them before the tests waiting in Acquire. A
// test whose subtests take labs in an order of its own (the censor
// matrix: its longest rows first) passes each one's place.
func (p *Pool) AcquireInOrder(t testing.TB, rank int) *Lab {
	t.Helper()
	return p.acquireFor(t, min(max(rank, 0), unranked-1))
}

func (p *Pool) acquireFor(t testing.TB, rank int) *Lab {
	t.Helper()
	asked := time.Now()
	dl, _ := labBudget.begin(testDeadline(t)).deadline(phaseSlotWait)
	pl, err := p.acquire(context.Background(), dl, rank, func(ctx context.Context) (*pooledLab, error) { return p.start(ctx, t) })
	if err != nil {
		t.Fatal(err)
	}
	since := time.Now()
	t.Cleanup(func() { p.giveBack(t, pl, since) })
	notePool("take", pl.lab.Project, fmt.Sprintf("use %d %s", pl.uses, t.Name()))
	t.Logf("lab %s (pool %s, use %d) after %v", pl.lab.Project, p.name, pl.uses, since.Sub(asked).Round(100*time.Millisecond))
	return pl.lab
}

// acquire is an idle lab, or one start starts under ctx (counted in
// p.labs: it adopts what it starts, or counts it out), waiting until
// deadline, in rank's place among the waiting, for one to come back when
// the pool is full; the lab's use is counted. While the start waits for
// its slot, a lab that comes back may serve instead (startOrTake).
func (p *Pool) acquire(ctx context.Context, deadline time.Time, rank int, start func(context.Context) (*pooledLab, error)) (*pooledLab, error) {
	pl, err := p.take(deadline, rank)
	if err != nil {
		return nil, err
	}
	if pl == nil {
		if pl, err = p.startOrTake(ctx, rank, start); err != nil {
			return nil, err
		}
	}
	p.mu.Lock()
	p.stats.Uses++
	p.mu.Unlock()
	pl.uses++
	return pl, nil
}

// take is an idle lab, or nil for the caller to start one, waiting until
// deadline, in rank's place among the waiting, for one to come back when
// the pool is full.
func (p *Pool) take(deadline time.Time, rank int) (*pooledLab, error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil, fmt.Errorf("lab: pool %s: closed", p.name)
	}
	p.takers--
	if n := len(p.idle); n > 0 {
		pl := p.idle[n-1]
		p.idle = p.idle[:n-1]
		pl.timer.Stop() // one that fired finds pl taken (idleCheck)
		p.mu.Unlock()
		return pl, nil
	}
	// A lab started first and still coming is a waiter's to have, not a
	// reason to start another.
	if p.labs < p.size && len(p.waiters) >= p.coming {
		p.labs++
		p.mu.Unlock()
		return nil, nil
	}
	ch := make(chan *pooledLab, 1)
	p.waiters = inRank(p.waiters, poolWaiter{ch: ch, rank: rank})
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
	if i := slices.IndexFunc(p.waiters, func(w poolWaiter) bool { return w.ch == ch }); i >= 0 {
		p.waiters = slices.Delete(p.waiters, i, i+1)
		p.mu.Unlock()
		return nil, fmt.Errorf("lab: pool %s: no lab came back within %v", p.name, time.Since(from).Round(time.Second))
	}
	p.mu.Unlock()
	return <-ch, nil // handed on meanwhile
}

// inRank puts w among ws after every one of its rank or lower.
func inRank(ws []poolWaiter, w poolWaiter) []poolWaiter {
	at := len(ws)
	for at > 0 && ws[at-1].rank > w.rank {
		at--
	}
	return slices.Insert(ws, at, w)
}

// startOrTake runs start, the caller's lab start that take let it make,
// and returns its lab; but a lab that comes back while no test waits in
// take goes to the caller first (a start's slot wait under load has taken
// 14 minutes while the pool's other lab sat idle). Then the start, no
// longer needed, leaves the slot queue (withSlotWaitStop) and is counted
// out; one that holds its slot already goes on, and its lab goes to the
// pool as any other.
func (p *Pool) startOrTake(ctx context.Context, rank int, start func(context.Context) (*pooledLab, error)) (*pooledLab, error) {
	ch := make(chan *pooledLab, 1)
	p.mu.Lock()
	p.starters = inRank(p.starters, poolWaiter{ch: ch, rank: rank})
	p.mu.Unlock()
	type started struct {
		pl  *pooledLab
		err error
	}
	done := make(chan started, 1)
	stop := make(chan struct{})
	go func() {
		pl, err := start(withSlotWaitStop(ctx, stop))
		done <- started{pl, err}
	}()
	select {
	case s := <-done:
		p.mu.Lock()
		defer p.mu.Unlock()
		if i := slices.IndexFunc(p.starters, func(w poolWaiter) bool { return w.ch == ch }); i >= 0 {
			p.starters = slices.Delete(p.starters, i, i+1)
			return s.pl, s.err
		}
		// A lab came back meanwhile as well.
		if s.pl != nil {
			p.putBack(s.pl)
		}
		return <-ch, nil
	case pl := <-ch:
		close(stop)
		p.down.Add(1)
		go func() {
			defer p.down.Done()
			s := <-done
			if s.err != nil {
				if !errors.Is(s.err, errSlotWaitStopped) {
					fmt.Fprintf(os.Stderr, "lab pool %s: a lab start no test needed any more: %v\n", p.name, s.err)
				}
				return
			}
			p.mu.Lock()
			defer p.mu.Unlock()
			p.putBack(s.pl)
		}()
		return pl, nil
	}
}

// start brings up a lab for the pool, which the caller counted in
// p.labs, and snapshots its clean state.
func (p *Pool) start(ctx context.Context, t testing.TB) (*pooledLab, error) {
	begin := time.Now()
	l, bins, keep, err := launch(ctx, t, p.topo, func(project string) string { return "pool:" + project }, "pool-"+p.name, os.Getenv(ProjectEnv))
	return p.adopt(l, startedLab{lab: l, bins: bins, keepEnv: keep}, begin, err)
}

// adopt takes l, which the pool counted in p.labs and began starting at
// begin, once it has snapshotted its clean state; a lab whose start (err)
// or snapshot failed is torn down and counted out.
func (p *Pool) adopt(l *Lab, ops pooledOps, begin time.Time, err error) (*pooledLab, error) {
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
	return &pooledLab{lab: l, ops: ops, clean: clean, took: time.Since(begin)}, nil
}

// giveBack resets the lab t had and puts it back (back), or retires it
// when t failed or the reset didn't hold. What the reset found to undo
// goes to t's log after the names of the users that had the lab before,
// so a failure that depends on their order can be traced.
func (p *Pool) giveBack(t labUser, pl *pooledLab, since time.Time) (back bool) {
	before := slices.Clone(pl.users)
	pl.users = append(pl.users, t.Name())
	if t.Failed() {
		p.retire(t, pl, "it failed")
		pl.ops.cleanup(t, since)
		p.gone()
		return false
	}
	var once sync.Once
	logf := func(format string, args ...any) {
		once.Do(func() {
			users := "none"
			if len(before) > 0 {
				users = strings.Join(before, ", ")
			}
			t.Logf("lab %s: the reset after this test, the users that had the lab before it: %s", pl.ops.name(), users)
		})
		t.Logf(format, args...)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	err := pl.ops.reset(ctx, pl.clean, logf)
	cancel()
	if err != nil {
		t.Logf("lab %s: the reset after this test didn't hold, so the lab goes: %v", pl.ops.name(), err)
		p.retire(t, pl, "its reset didn't hold")
		if !pl.ops.keep(t) {
			ctx, cancel := context.WithTimeout(context.Background(), labBudget.teardown)
			if err := pl.ops.down(ctx); err != nil {
				t.Errorf("lab %s: tear down: %v", pl.ops.name(), err)
			}
			cancel()
		}
		p.gone()
		return false
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.putBack(pl)
	return true
}

// putBack gives pl, clean, to the first waiter, or keeps it idle; a
// closed pool's (a start no test waited for, done after the run) goes.
// p.mu is held.
func (p *Pool) putBack(pl *pooledLab) {
	if p.closed {
		p.labs--
		p.down.Add(1)
		go func() {
			defer p.down.Done()
			p.teardown(pl, "end of the run")
		}()
		return
	}
	if p.handOn(pl) {
		return
	}
	pl.since = time.Now()
	pl.timer = time.AfterFunc(poolIdleCheck, func() { p.idleCheck(pl) })
	p.idle = append(p.idle, pl)
	p.trimIdle()
}

// countTakers says that takers users may still take one of the pool's
// labs; each take counts one out, and skip counts out one that won't take
// any after all.
func (p *Pool) countTakers(takers int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.takers, p.takersKnown = takers, true
}

// skip counts out a user countTakers counted that won't take a lab.
func (p *Pool) skip() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.takers--
	p.trimIdle()
}

// trimIdle tears down the idle labs beyond the users that may still take
// one, the longest idle first. p.mu is held.
func (p *Pool) trimIdle() {
	for p.takersKnown && len(p.idle) > max(p.takers, 0) {
		pl := p.idle[0]
		p.idle = p.idle[1:]
		pl.timer.Stop() // one that fired finds pl gone (idleCheck)
		p.labs--
		p.handOn(nil)
		p.down.Add(1)
		go func() {
			defer p.down.Done()
			p.teardown(pl, "no user left for it")
		}()
	}
}

func (p *Pool) retire(t labUser, pl *pooledLab, why string) {
	notePool("retire", pl.ops.name(), fmt.Sprintf("%s: %s", t.Name(), why))
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

// came puts a lab started first (StartFirst) back, or for a start that
// failed (nil, which adopt counted out), lets the waiters beyond the labs
// still coming start one. p.mu is held.
func (p *Pool) came(pl *pooledLab) {
	p.coming--
	if pl == nil {
		for len(p.waiters) > p.coming && p.labs < p.size {
			p.handOn(nil)
		}
		return
	}
	p.putBack(pl)
}

// handOn gives pl (nil: leave to start one) to the first waiter, if any,
// else pl to the first test whose own start waits (startOrTake). p.mu is
// held.
func (p *Pool) handOn(pl *pooledLab) bool {
	if len(p.waiters) > 0 {
		ch := p.waiters[0].ch
		p.waiters = p.waiters[1:]
		if pl == nil {
			p.labs++
		}
		ch <- pl
		return true
	}
	if pl != nil && len(p.starters) > 0 {
		ch := p.starters[0].ch
		p.starters = p.starters[1:]
		ch <- pl
		return true
	}
	return false
}

// idleCheck tears down pl if it is still idle and has been for long
// enough (poolIdle, poolIdleMax), or looks again later.
func (p *Pool) idleCheck(pl *pooledLab) {
	wanted := true
	if p.slotWanted != nil {
		wanted = p.slotWanted()
	} else if dir, err := lockDir(); err == nil {
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
	notePool("down", pl.ops.name(), fmt.Sprintf("%s after %d uses", why, pl.uses))
	ctx, cancel := context.WithTimeout(context.Background(), labBudget.teardown)
	defer cancel()
	if err := pl.ops.down(ctx); err != nil {
		p.mu.Lock()
		p.downErrs = append(p.downErrs, fmt.Errorf("lab %s: tear down: %w", pl.ops.name(), err))
		p.mu.Unlock()
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

// closePools closes every pool (close) at once.
func closePools(w io.Writer) {
	poolsMu.Lock()
	all := slices.Clone(pools)
	poolsMu.Unlock()
	var wg sync.WaitGroup
	for _, p := range all {
		p.closeIdle(&wg)
	}
	wg.Wait()
	for _, p := range all {
		p.report(w, "tests")
		p.mu.Lock()
		for _, err := range p.downErrs {
			_, _ = fmt.Fprintln(w, err)
		}
		p.mu.Unlock()
	}
}

// close tears down the pool's idle labs, waits for those already going,
// and writes its stats to w, counting its users as users: the pool takes
// no lab back after. The error is its idle labs' tear-downs that failed.
func (p *Pool) close(w io.Writer, users string) error {
	var wg sync.WaitGroup
	p.closeIdle(&wg)
	wg.Wait()
	p.report(w, users)
	p.mu.Lock()
	defer p.mu.Unlock()
	return errors.Join(p.downErrs...)
}

// closeIdle closes the pool and tears its idle labs down in wg.
func (p *Pool) closeIdle(wg *sync.WaitGroup) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	idle := p.idle
	p.idle = nil
	p.labs -= len(idle)
	for _, pl := range idle {
		pl.timer.Stop()
		wg.Go(func() { p.teardown(pl, "end of the run") })
	}
}

// report waits for the idle labs going down, then writes the pool's stats
// to w, if it was used.
func (p *Pool) report(w io.Writer, users string) {
	p.down.Wait()
	if s := p.Stats(); s.Uses > 0 {
		_, _ = fmt.Fprintf(w, "lab pool %s: %d labs started for %d %s, %d retired\n", p.name, s.Started, s.Uses, users, len(s.Retired))
		for _, r := range s.Retired {
			_, _ = fmt.Fprintf(w, "lab pool %s: retired after %s\n", p.name, r)
		}
	}
}
