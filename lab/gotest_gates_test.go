package lab

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// gateSteps are a fake package's steps through goTestGates.run, counting
// how many packages are in each phase at once.
type gateSteps struct {
	building, inLab    atomic.Int32
	maxBuild, maxLab   atomic.Int32
	builds, labRuns    atomic.Int32
	buildHold, labHold time.Duration
}

func raise(m *atomic.Int32, v int32) {
	for {
		old := m.Load()
		if v <= old || m.CompareAndSwap(old, v) {
			return
		}
	}
}

func (s *gateSteps) prepare() error { return nil }

func (s *gateSteps) build(needsLab bool) func() bool {
	return func() bool {
		raise(&s.maxBuild, s.building.Add(1))
		time.Sleep(s.buildHold)
		s.building.Add(-1)
		s.builds.Add(1)
		return needsLab
	}
}

func (s *gateSteps) labRun(time.Time) {
	raise(&s.maxLab, s.inLab.Add(1))
	time.Sleep(s.labHold)
	s.inLab.Add(-1)
	s.labRuns.Add(1)
}

// bounded is a context that ends a test's wait instead of hanging it.
func bounded(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// GoTestEach's gates fill to their caps, and no further: Builds packages
// build at once and Labs run in labs at once.
func TestGoTestGatesBoundEachPhase(t *testing.T) {
	const packages = 24
	g := newGoTestGates(GoTestConcurrency{Labs: 5, Builds: 2}, packages)
	s := &gateSteps{buildHold: 10 * time.Millisecond, labHold: 100 * time.Millisecond}
	ctx := bounded(t)
	var wg sync.WaitGroup
	for range packages {
		wg.Go(func() {
			if err := g.run(ctx, s.prepare, s.build(true), s.labRun); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if got := s.maxBuild.Load(); got != 2 {
		t.Errorf("%d packages built at once, want 2 (Builds)", got)
	}
	if got := s.maxLab.Load(); got != 5 {
		t.Errorf("%d packages in labs at once, want 5 (Labs)", got)
	}
	if b, l := s.builds.Load(), s.labRuns.Load(); b != packages || l != packages {
		t.Errorf("%d builds and %d lab runs, want %d of each", b, l, packages)
	}
}

// A package gives its build token back before it waits for a lab: with one
// build token, the next package builds while the first is in its lab.
func TestGoTestGatesBuildTokenFreeDuringLab(t *testing.T) {
	g := newGoTestGates(GoTestConcurrency{Labs: 2, Builds: 1}, 2)
	ctx := bounded(t)
	secondBuilt, inLab := make(chan struct{}), make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- g.run(ctx, func() error { return nil }, func() bool { return true }, func(time.Time) {
			close(inLab)
			select {
			case <-secondBuilt:
			case <-ctx.Done():
				t.Error("the second package never built while the first was in its lab")
			}
		})
	}()
	<-inLab
	if err := g.run(ctx, func() error { return nil }, func() bool { close(secondBuilt); return false }, func(time.Time) {}); err != nil {
		t.Fatal(err)
	}
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

// A package served from the cache (build says no lab) never takes a lab
// token: with the only lab held, it still finishes.
func TestGoTestGatesCachedPackageTakesNoLab(t *testing.T) {
	g := newGoTestGates(GoTestConcurrency{Labs: 1, Builds: 2}, 2)
	ctx := bounded(t)
	cachedDone := make(chan struct{})
	inLab := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- g.run(ctx, func() error { return nil }, func() bool { return true }, func(time.Time) {
			close(inLab)
			select {
			case <-cachedDone:
			case <-ctx.Done():
				t.Error("the cached package waited for the lab the first package held")
			}
		})
	}()
	<-inLab
	ranLab := false
	if err := g.run(ctx, func() error { return nil }, func() bool { return false }, func(time.Time) { ranLab = true }); err != nil {
		t.Fatal(err)
	}
	close(cachedDone)
	if ranLab {
		t.Error("a package whose build said no lab ran in one")
	}
	if err := <-first; err != nil {
		t.Fatal(err)
	}
}

// A package whose prepare or build fails gives its build token back: with
// one build token, the next package still builds.
func TestGoTestGatesFailedBuildReturnsToken(t *testing.T) {
	g := newGoTestGates(GoTestConcurrency{Labs: 1, Builds: 1}, 3)
	ctx := bounded(t)
	broken := errors.New("prepare failed")
	if err := g.run(ctx, func() error { return broken }, func() bool { t.Error("built after a failed prepare"); return true }, func(time.Time) {}); !errors.Is(err, broken) {
		t.Fatalf("a failed prepare: %v, want its error", err)
	}
	if err := g.run(ctx, func() error { return nil }, func() bool { return false }, func(time.Time) {}); err != nil { // a failed build: no lab
		t.Fatalf("after a failed prepare: %v", err)
	}
	built := false
	if err := g.run(ctx, func() error { return nil }, func() bool { built = true; return false }, func(time.Time) {}); err != nil || !built {
		t.Fatalf("after a failed build: %v, built %v", err, built)
	}
}

// A package queued for a token when the run's context ends starts nothing
// more: it returns the context's error and its later steps don't run.
func TestGoTestGatesQueuedPackageStopsWithContext(t *testing.T) {
	for _, phase := range []string{"build", "lab"} {
		t.Run(phase, func(t *testing.T) {
			g := newGoTestGates(GoTestConcurrency{Labs: 1, Builds: 1}, 2)
			ctx, cancel := context.WithCancel(bounded(t))
			held, release := make(chan struct{}), make(chan struct{})
			holder := make(chan error, 1)
			hold := func(time.Time) { close(held); <-release }
			go func() {
				if phase == "build" {
					holder <- g.run(ctx, func() error { return nil }, func() bool { hold(time.Time{}); return false }, func(time.Time) {})
				} else {
					holder <- g.run(ctx, func() error { return nil }, func() bool { return true }, hold)
				}
			}()
			<-held
			// Cancelled while the package below waits for the held token.
			time.AfterFunc(50*time.Millisecond, cancel)
			var prepared, ranLab atomic.Bool
			queued := make(chan error, 1)
			go func() {
				queued <- g.run(ctx, func() error { prepared.Store(true); return nil }, func() bool { return true }, func(time.Time) { ranLab.Store(true) })
			}()
			var err error
			select {
			case err = <-queued:
			case <-time.After(5 * time.Second):
				t.Fatalf("queued behind a held %s token: still waiting 5 s after the context was cancelled", phase)
			}
			close(release)
			<-holder
			if !errors.Is(err, context.Canceled) {
				t.Errorf("queued behind a held %s token, the context cancelled: %v, want context.Canceled", phase, err)
			}
			if ranLab.Load() || (phase == "build" && prepared.Load()) {
				t.Errorf("queued behind a held %s token, the context cancelled: prepared %v, ran in a lab %v", phase, prepared.Load(), ranLab.Load())
			}
		})
	}
}

// With BuildAllFirst (a perf run) no lab starts until every package is
// past its build steps, the cached and failed ones included.
func TestGoTestGatesBuildAllFirst(t *testing.T) {
	const packages = 6
	g := newGoTestGates(GoTestConcurrency{Labs: 2, Builds: 1, BuildAllFirst: true}, packages)
	ctx := bounded(t)
	s := &gateSteps{buildHold: 5 * time.Millisecond, labHold: 5 * time.Millisecond}
	var wg sync.WaitGroup
	for i := range packages {
		wg.Go(func() {
			lab := func(queued time.Time) {
				if got := s.builds.Load(); got != packages-1 { // the failed prepare never builds
					t.Errorf("a lab started with %d of %d builds done", got, packages-1)
				}
				s.labRun(queued)
			}
			prepare := s.prepare
			if i == 0 {
				prepare = func() error { return errors.New("prepare failed") }
			}
			_ = g.run(ctx, prepare, s.build(i%2 == 0), lab)
		})
	}
	wg.Wait()
	if got := s.labRuns.Load(); got != 2 { // i = 2, 4
		t.Errorf("%d lab runs, want 2", got)
	}
}

// labRun gets when its package began to queue for a lab token: with the
// only lab held, the second package's queue spans the hold.
func TestGoTestGatesTimeTheLabQueue(t *testing.T) {
	g := newGoTestGates(GoTestConcurrency{Labs: 1, Builds: 2}, 2)
	ctx := bounded(t)
	const hold = 200 * time.Millisecond
	inLab := make(chan struct{})
	first := make(chan error, 1)
	go func() {
		first <- g.run(ctx, func() error { return nil }, func() bool { return true }, func(time.Time) {
			close(inLab)
			time.Sleep(hold)
		})
	}()
	<-inLab
	var queuedFor time.Duration
	if err := g.run(ctx, func() error { return nil }, func() bool { return true }, func(queued time.Time) { queuedFor = time.Since(queued) }); err != nil {
		t.Fatal(err)
	}
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if queuedFor < hold/2 {
		t.Errorf("queued %v behind a lab held %v", queuedFor, hold)
	}
}
