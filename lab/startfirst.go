package lab

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

// The longest lab tests start their labs first. go test resumes a
// package's parallel tests all at once, once every test's serial part has
// run (make lab-test's -parallel lets every one of them run), and they
// race for the slot queue, first come first served. A test calls
// StartFirst (or Pool.StartFirst) in place of t.Parallel: in its serial
// part, before any parallel test runs, that counts its lab starts in, and
// every other lab start of the process waits to join the slot queue until
// those have joined it (firstStarts). The starts themselves begin once the
// test resumes, with the others: serial tests (the harness's unit tests)
// set TMPDIR and the slot cap for themselves, which a start running beside
// them would read.
//
// Only in a stream (StreamEnv: make lab-test), where every test runs: a
// run by hand may run only some of a test's subtests (go test -run
// Test/part), and starts only the labs its tests take.

// firstStarts holds back the slot waits of this process's lab starts
// while a lab start StartFirst counted in hasn't joined the slot queue of
// the same lock directory yet.
var firstStarts = startOrder{waves: map[string]*firstWave{}}

// firstLaunchGrace is how long a slot wait waits for the first starts to
// begin before it takes itself for a serial test's: they begin when their
// test resumes after the serial parts, so a serial test that started a
// lab after StartFirst would wait for them forever.
var firstLaunchGrace = 30 * time.Second

type startOrder struct {
	mu    sync.Mutex
	waves map[string]*firstWave // by lock directory
}

// firstWave is a lock directory's first starts.
type firstWave struct {
	pending  int           // counted in, not yet in the slot queue
	clear    chan struct{} // closed once pending drops to 0
	launched chan struct{} // closed once one of them began
	once     sync.Once
}

// hold counts a first start in for dir's slot queue. The start calls
// launch when it begins and joined once it joined the queue (or gave up);
// both are safe to call again.
func (o *startOrder) hold(dir string) (launch, joined func()) {
	o.mu.Lock()
	w := o.waves[dir]
	if w == nil || w.pending == 0 {
		w = &firstWave{clear: make(chan struct{}), launched: make(chan struct{})}
		o.waves[dir] = w
	}
	w.pending++
	o.mu.Unlock()
	var once sync.Once
	return func() { w.once.Do(func() { close(w.launched) }) }, func() {
		once.Do(func() {
			o.mu.Lock()
			defer o.mu.Unlock()
			w.pending--
			if w.pending == 0 {
				close(w.clear)
			}
		})
	}
}

// wait returns once no first start of dir's is waiting to join its slot
// queue, or with an error: ctx ended, or none of them began within
// firstLaunchGrace.
func (o *startOrder) wait(ctx context.Context, dir string) error {
	o.mu.Lock()
	w := o.waves[dir]
	if w == nil || w.pending == 0 {
		o.mu.Unlock()
		return nil
	}
	o.mu.Unlock()
	grace := time.NewTimer(firstLaunchGrace)
	defer grace.Stop()
	select {
	case <-w.clear:
		return nil
	case <-w.launched:
	case <-grace.C:
		return fmt.Errorf("lab: this lab start waited %v for the labs StartFirst counted in, which begin only once every serial test has run: "+
			"a serial test started a lab in a package that has StartFirst tests; call t.Parallel in that test before its lab start", firstLaunchGrace)
	case <-ctx.Done():
		return fmt.Errorf("lab: waiting for the labs started first to join the slot queue: %w", ctx.Err())
	}
	select {
	case <-w.clear:
		return nil
	case <-ctx.Done():
		return fmt.Errorf("lab: waiting for the labs started first to join the slot queue: %w", ctx.Err())
	}
}

type firstStartKey struct{}

// asFirstStart marks a lab start's ctx as a first start: its slot wait
// doesn't wait for firstStarts, and calls joined once it joined the slot
// queue.
func asFirstStart(ctx context.Context, joined func()) context.Context {
	return context.WithValue(ctx, firstStartKey{}, joined)
}

// slotQueueShare is how many of a process's slot waits, first starts
// aside, stand in a lock directory's slot queue at once (0: no bound). The
// queue is first come first served, and make lab-test's lab/ phase runs
// every test at once: without a share, the starts it queues at once would
// all go before those of its node phase and of other runs. A share per
// process interleaves them as slots free up; a process's own waits take
// their turns among themselves.
var slotQueueShare = 2

var (
	queueSharesMu sync.Mutex
	queueShares   = map[string]chan struct{}{} // by lock directory
)

// slotOrder is what a slot wait in dir under ctx does before it joins the
// slot queue: a first start goes on; any other waits for the first ones,
// then for a place in the process's share of the queue (slotQueueShare),
// which leave gives back once the wait is over.
func slotOrder(ctx context.Context, dir string) (leave func(), err error) {
	if _, first := ctx.Value(firstStartKey{}).(func()); first {
		return func() {}, nil
	}
	if err := firstStarts.wait(ctx, dir); err != nil {
		return nil, err
	}
	queueSharesMu.Lock()
	share, ok := queueShares[dir]
	if !ok && slotQueueShare > 0 {
		share = make(chan struct{}, slotQueueShare)
		queueShares[dir] = share
	}
	queueSharesMu.Unlock()
	if share == nil {
		return func() {}, nil
	}
	select {
	case share <- struct{}{}:
		return func() { <-share }, nil
	case <-ctx.Done():
		return nil, fmt.Errorf("lab: waiting for this process's turn in the slot queue: %w", ctx.Err())
	}
}

// joinedSlotQueue tells a first start's StartFirst that its slot wait
// joined the slot queue (or gave up on it).
func joinedSlotQueue(ctx context.Context) {
	if joined, ok := ctx.Value(firstStartKey{}).(func()); ok {
		joined()
	}
}

// startFirst counts in, in t's serial part, the first starts count says
// (it is called once nothing can fail t before them), then calls
// t.Parallel, and runs each start (launch then joined) once t resumes. It
// returns a func that waits for every start to end; without a stream,
// count isn't called and nothing starts.
func startFirst(t *testing.T, count func() int, start func(ctx context.Context)) (wait func()) {
	t.Helper()
	s, err := Stream()
	if err != nil {
		t.Fatal(err)
	}
	if s == "" {
		t.Parallel()
		return func() {}
	}
	dir, err := lockDir()
	if err != nil {
		t.Fatal(err)
	}
	n := max(count(), 0)
	type held struct{ launch, joined func() }
	holds := make([]held, n)
	for i := range holds {
		holds[i].launch, holds[i].joined = firstStarts.hold(dir)
	}
	t.Parallel()
	var wg sync.WaitGroup
	for _, h := range holds {
		h.launch()
		wg.Go(func() {
			defer h.joined()
			start(asFirstStart(context.Background(), h.joined))
		})
	}
	return wg.Wait
}

// FirstLabs are the labs StartFirst started for a test's subtests, each
// taken by one of them (Take).
type FirstLabs struct {
	topo    Topology
	started chan firstLab // nil: none started (not in a stream)

	mu    sync.Mutex
	taken int
	n     int
}

type firstLab struct {
	lab  *Lab
	bins *runBinaries
	keep bool
	err  error
}

// StartFirst calls t.Parallel and starts n labs of topo for t's subtests,
// each with a slot of its own as StartOwnSlot's, ahead of every lab start
// of the process's other tests (see above); t calls it in place of
// t.Parallel. Its subtests take them with Take; a lab no subtest took is
// torn down when t ends. Outside a stream it starts nothing, and Take
// starts the subtest's lab (StartOwnSlot).
func StartFirst(t *testing.T, topo Topology, n int) *FirstLabs {
	t.Helper()
	if err := topo.Validate(); err != nil {
		t.Fatal(err)
	}
	f := &FirstLabs{topo: topo, n: n}
	wait := startFirst(t, func() int {
		if n > 0 {
			f.started = make(chan firstLab, n)
		}
		return n
	}, func(ctx context.Context) {
		l, bins, keep, err := launch(ctx, t, topo, func(project string) string { return "first:" + project }, t.Name(), os.Getenv(ProjectEnv))
		f.started <- firstLab{l, bins, keep, err}
	})
	t.Cleanup(func() {
		wait()
		for {
			select {
			case fl := <-f.started:
				if fl.lab != nil {
					fl.lab.cleanup(t, fl.bins, fl.keep, time.Time{})
				}
			default:
				return
			}
		}
	})
	return f
}

// Take gives the subtest t one of the labs StartFirst started, waiting
// for its start, and tears it down when t ends, as StartOwnSlot does; once
// they are all taken, or outside a stream, it starts one (StartOwnSlot).
func (f *FirstLabs) Take(t testing.TB) *Lab {
	t.Helper()
	f.mu.Lock()
	first := f.started != nil && f.taken < f.n
	if first {
		f.taken++
	}
	f.mu.Unlock()
	if !first {
		return StartOwnSlot(t, f.topo)
	}
	fl := <-f.started
	if fl.lab != nil {
		t.Cleanup(func() { fl.lab.cleanup(t, fl.bins, fl.keep, time.Time{}) })
	}
	if fl.err != nil {
		t.Fatal(fl.err)
	}
	return fl.lab
}

// StartFirst calls t.Parallel and starts up to n of the pool's labs (no
// more than it has room for) for t's tests, ahead of every lab start of
// the process's other tests (see above); t calls it in place of
// t.Parallel. They go to the pool's waiting tests, or wait idle in it, as
// any of its labs: a test that finds none idle waits for one of them,
// rather than start a lab, while more are coming than tests wait. A start
// that failed fails t, and the next waiting test starts a lab instead.
// Outside a stream it starts nothing.
func (p *Pool) StartFirst(t *testing.T, n int) {
	t.Helper()
	wait := startFirst(t, func() int {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.closed {
			return 0
		}
		n = max(min(n, p.size-p.labs), 0)
		p.labs += n
		p.coming += n
		return n
	}, func(ctx context.Context) {
		pl, err := p.start(ctx, t)
		if err != nil {
			t.Errorf("lab pool %s: a lab started first: %v", p.name, err)
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		p.came(pl)
	})
	t.Cleanup(wait)
}
