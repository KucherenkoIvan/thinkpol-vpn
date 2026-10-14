package routetable_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// The guard lets out around the tunnel exactly what the table throws,
// the links' marked sockets, and the direct DNS upstreams the table
// routes.
func TestGuardForIsWhatTheTableThrows(t *testing.T) {
	w := routetable.Want{
		TUN:     "thinkpol0",
		Overlay: overlay,
		Direct:  set(t, "198.51.100.0/24", "2001:db8:d0::/48"),
		Bypass:  []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8:7::7"), netip.MustParseAddr("::ffff:203.0.113.8"), {}},
		IPv6:    true,
		Upstreams: []netip.Addr{netip.MustParseAddr("2001:db8:53::1"), netip.MustParseAddr("::ffff:192.0.2.53"),
			netip.MustParseAddr("2001:db8:53::1"), {}},
	}
	want := routetable.Exempt{TUN: "thinkpol0", Mark: routetable.Mark,
		Direct:    set(t, "198.51.100.0/24", "2001:db8:d0::/48", "203.0.113.7/32", "203.0.113.8/32", "2001:db8:7::7/128"),
		Upstreams: []netip.Addr{netip.MustParseAddr("192.0.2.53"), netip.MustParseAddr("2001:db8:53::1")}}
	if got := routetable.GuardFor(w); !got.Equal(want) {
		t.Errorf("GuardFor: %+v, want %+v", got, want)
	}
	for _, a := range []string{"fd12:3456:789a::9", "2001:4860::8888"} {
		if routetable.GuardFor(w).Direct.Contains(netip.MustParseAddr(a)) {
			t.Errorf("%s exempt: neither direct nor an endpoint", a)
		}
	}
}

// fakeGuard records what it is given, and when: how many route Applies
// the configurator had seen by then; the test signals its Watch.
type fakeGuard struct {
	f       *fakeConfigurator
	events  chan struct{}
	mu      sync.Mutex
	applied []routetable.Exempt
	after   []int
	failErr error
	closed  bool
	order   *[]string    // what was closed, in order
	watches atomic.Int32 // subscriptions alive
}

func newFakeGuard(f *fakeConfigurator) *fakeGuard {
	return &fakeGuard{f: f, events: make(chan struct{})}
}

func (g *fakeGuard) Apply(_ context.Context, e routetable.Exempt) error {
	n := g.f.count()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failErr != nil {
		return g.failErr
	}
	g.applied = append(g.applied, e)
	g.after = append(g.after, n)
	return nil
}

func (g *fakeGuard) Watch(ctx context.Context) (<-chan struct{}, error) {
	out := make(chan struct{})
	g.watches.Add(1)
	go func() {
		defer g.watches.Add(-1)
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case <-g.events:
				select {
				case out <- struct{}{}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	return out, nil
}

func (g *fakeGuard) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.applied)
}

func (g *fakeGuard) setFail(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.failErr = err
}

func (g *fakeGuard) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	if g.order != nil {
		*g.order = append(*g.order, "guard")
	}
	return nil
}

func TestEnforcerAppliesTheGuardWithTheRoutes(t *testing.T) {
	f := &fakeConfigurator{events: make(chan struct{}), survey: up()}
	g := newFakeGuard(f)
	e := routetable.OpenWithGuard(f, g, nil)
	ctx := context.Background()
	if st := e.Status(); st.GuardEnforced || st.GuardError != "" {
		t.Errorf("guard status before the first Enforce: %+v", st)
	}
	w := routetable.Want{TUN: "thinkpol0", Direct: set(t, "2001:db8:d0::/48")}
	if err := e.Enforce(ctx, w); err != nil {
		t.Fatal(err)
	}
	g.mu.Lock()
	first, after := g.applied[0], g.after[0]
	g.mu.Unlock()
	if !first.Equal(routetable.GuardFor(w)) || after != 1 {
		t.Errorf("guard %+v after %d route Applies, want %+v after the first", first, after, routetable.GuardFor(w))
	}
	if st := e.Status(); !st.Enforced || !st.GuardEnforced || st.GuardError != "" {
		t.Errorf("status %+v", st)
	}
	// Every re-Apply checks the guard too (someone may have removed it).
	eventually(t, "the check after Enforce", func() bool { return e.Status().Reapplies == 1 })
	if n := g.count(); n != 2 {
		t.Errorf("%d guard Applies after the re-Apply, want 2", n)
	}

	// The guard's own Watch puts the guard back alone: no route Apply.
	routes := f.count()
	g.events <- struct{}{}
	eventually(t, "the guard put back after its Watch", func() bool { return g.count() == 3 })
	if f.count() != routes {
		t.Errorf("the guard's event re-applied the routes (%d Applies, want %d)", f.count(), routes)
	}

	// Routes that fail leave the routes in place, and the guard checked
	// for them, not for the Want that failed.
	f.setFail(true)
	w2 := w
	w2.Direct = nil
	if err := e.Enforce(ctx, w2); err == nil {
		t.Fatal("Enforce succeeded on a failing configurator")
	}
	g.mu.Lock()
	last := g.applied[len(g.applied)-1]
	g.mu.Unlock()
	if !last.Equal(routetable.GuardFor(w)) {
		t.Errorf("after the routes failed the guard was applied for %+v, want the routes in place", last)
	}
	f.setFail(false)

	// A guard that fails doesn't fail the Enforce or the routes: its own
	// status says it, and it is retried.
	g.setFail(errors.New("nftables said no"))
	if err := e.Enforce(ctx, w2); err != nil {
		t.Fatalf("Enforce failed with the guard: %v", err)
	}
	if st := e.Status(); !st.Enforced || st.Error != "" || st.GuardEnforced || st.GuardError != routetable.ErrorGuard {
		t.Errorf("status with a failing guard: %+v", st)
	}
	g.setFail(nil)
	eventually(t, "the guard retried within RetryAfter", func() bool { return e.Status().GuardEnforced })
	g.mu.Lock()
	last = g.applied[len(g.applied)-1]
	g.mu.Unlock()
	if !last.Equal(routetable.GuardFor(w2)) {
		t.Errorf("the retry applied %+v, want %+v", last, routetable.GuardFor(w2))
	}

	// Close removes the guard before the routes let go of the owner lock.
	var order []string
	g.mu.Lock()
	g.order = &order
	g.mu.Unlock()
	f.mu.Lock()
	f.order = &order
	f.mu.Unlock()
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "guard" || order[1] != "routes" {
		t.Errorf("Close closed %v, want the guard, then the routes", order)
	}
}

// An OS that can't hold the guard (no nf_tables) stops the guard for
// good, loudly, and the routes carry on.
func TestEnforcerStopsTheGuardWhenUnsupported(t *testing.T) {
	f := &fakeConfigurator{events: make(chan struct{}), survey: up()}
	g := newFakeGuard(f)
	g.setFail(fmt.Errorf("firewall: nftables: %w", routetable.ErrGuardUnsupported))
	e := routetable.OpenWithGuard(f, g, nil)
	defer func() { _ = e.Close() }()
	w := routetable.Want{TUN: "thinkpol0"}
	if err := e.Enforce(context.Background(), w); err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if st := e.Status(); !st.Enforced || st.GuardEnforced || st.GuardError != routetable.ErrorGuardUnsupported {
		t.Errorf("status %+v", st)
	}
	g.setFail(nil)
	// Nothing listens to the guard any more, and nothing retries it.
	select {
	case g.events <- struct{}{}:
	case <-time.After(routetable.RetryAfter + time.Second):
	}
	if n := g.count(); n != 0 {
		t.Errorf("%d guard Applies after it was unsupported, want none", n)
	}
	if st := e.Status(); st.GuardError != routetable.ErrorGuardUnsupported {
		t.Errorf("status later: %+v", st)
	}
}

// While the routes' re-apply keeps failing, the routes last applied stay
// in place (an Apply is all or nothing) and so must their guard: a guard
// deleted meanwhile is put back, for those routes, and the status says
// how that went the whole time.
func TestTheGuardIsPutBackWhileTheRoutesFail(t *testing.T) {
	f := &fakeConfigurator{events: make(chan struct{}), survey: up()}
	g := newFakeGuard(f)
	e := routetable.OpenWithGuard(f, g, nil)
	defer func() { _ = e.Close() }()
	ctx := context.Background()
	w := routetable.Want{TUN: "thinkpol0", Direct: set(t, "2001:db8:d0::/48")}
	if err := e.Enforce(ctx, w); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the check after Enforce", func() bool { return e.Status().Reapplies == 1 })

	// The routes start failing: a re-apply after a routing event, and a
	// new Want, both refused.
	f.setFail(true)
	f.events <- struct{}{}
	eventually(t, "the failed re-apply", func() bool { return e.Status().Error == routetable.ErrorReapply })
	w2 := w
	w2.Direct = set(t, "2001:db8:d1::/48")
	if err := e.Enforce(ctx, w2); err == nil {
		t.Fatal("Enforce succeeded on a failing configurator")
	}

	// The guard is deleted ("nft flush ruleset"): its Apply fails once,
	// which the status says, then works; each time for w, whose routes
	// are the ones in place.
	g.setFail(errors.New("the table is gone and nftables said no"))
	n := g.count()
	g.events <- struct{}{}
	eventually(t, "the guard's failure in the status while the routes fail", func() bool {
		st := e.Status()
		return !st.GuardEnforced && st.GuardError == routetable.ErrorGuard && st.Error != ""
	})
	g.setFail(nil)
	g.events <- struct{}{}
	eventually(t, "the guard back while the routes fail", func() bool {
		st := e.Status()
		return st.GuardEnforced && st.GuardError == "" && st.Error != "" && g.count() > n
	})
	g.mu.Lock()
	last := g.applied[len(g.applied)-1]
	g.mu.Unlock()
	if !last.Equal(routetable.GuardFor(w)) {
		t.Errorf("the guard put back for %+v, want the routes in place: %+v", last.Direct.Prefixes(), routetable.GuardFor(w).Direct.Prefixes())
	}

	// The routes' own retry (every RetryAfter) checks the guard too,
	// without a guard event.
	n = g.count()
	eventually(t, "a route retry checking the guard", func() bool { return g.count() > n })
	f.setFail(false)
	eventually(t, "the routes back", func() bool { return e.Status().Enforced })
}

// A watcher that stops on its own (a kernel without rule protocols: no
// route table to keep) lets go of its subscriptions, the guard's
// included, without waiting for Close.
func TestAWatcherThatStopsLetsGoOfItsSubscriptions(t *testing.T) {
	f := &fakeConfigurator{events: make(chan struct{}), fail: true, failErr: fmt.Errorf("netcfg: old kernel: %w", errors.ErrUnsupported)}
	g := newFakeGuard(f)
	e := routetable.OpenWithGuard(f, g, nil)
	defer func() { _ = e.Close() }()
	if err := e.Enforce(context.Background(), routetable.Want{TUN: "thinkpol0"}); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("Enforce: %v", err)
	}
	eventually(t, "the guard subscribed", func() bool { return g.watches.Load() > 0 })
	eventually(t, "the guard's subscription let go", func() bool { return g.watches.Load() == 0 })
}

// Clear removes a crashed run's guard only while it holds the route
// table's owner lock: when the configurator can't be had, for whatever
// reason (another live run, too many open files, a netlink failure
// after the lock was let go), the guard there may be live and stays.
func TestClearTouchesTheGuardOnlyUnderTheOwnerLock(t *testing.T) {
	for _, fail := range []error{netcfg.ErrBusy, syscall.EMFILE, errors.New("netlink: handle: no buffer space")} {
		g := newFakeGuard(&fakeConfigurator{})
		err := routetable.ClearWith(func() (netcfg.Configurator, error) { return nil, fail }, g)
		if !errors.Is(err, fail) || g.closed {
			t.Errorf("configurator failing with %v: Clear %v, guard closed %v", fail, err, g.closed)
		}
	}
	var order []string
	f := &fakeConfigurator{order: &order}
	g := newFakeGuard(f)
	g.order = &order
	if err := routetable.ClearWith(func() (netcfg.Configurator, error) { return f, nil }, g); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != "guard" || order[1] != "routes" {
		t.Errorf("Clear closed %v, want the guard, then the routes (letting go of the lock)", order)
	}
}

// The direct DNS upstreams the table routes (Want.Upstreams) are what
// the guard exempts: a change of upstreams alone reaches both, with no
// second channel to the guard.
func TestTheGuardFollowsTheDirectUpstreams(t *testing.T) {
	f := &fakeConfigurator{events: make(chan struct{}), survey: up()}
	g := newFakeGuard(f)
	e := routetable.OpenWithGuard(f, g, nil)
	defer func() { _ = e.Close() }()
	ctx := context.Background()
	w := routetable.Want{TUN: "thinkpol0", Direct: set(t, "2001:db8:d0::/48")}
	if err := e.Enforce(ctx, w); err != nil {
		t.Fatal(err)
	}
	w.Upstreams = []netip.Addr{netip.MustParseAddr("2001:db8:53::1")}
	routes := f.count()
	if err := e.Enforce(ctx, w); err != nil {
		t.Fatal(err)
	}
	if f.count() == routes {
		t.Error("new upstreams didn't reach the routes")
	}
	g.mu.Lock()
	last := g.applied[len(g.applied)-1]
	g.mu.Unlock()
	if !slices.Equal(last.Upstreams, w.Upstreams) {
		t.Errorf("the guard exempts upstreams %v, want %v", last.Upstreams, w.Upstreams)
	}
}
