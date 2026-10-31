package routetable_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
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
		Upstreams: []netip.AddrPort{netip.MustParseAddrPort("[2001:db8:53::1]:53"), netip.MustParseAddrPort("[::ffff:192.0.2.53]:53"),
			netip.MustParseAddrPort("[2001:db8:53::1]:53"), {}},
	}
	want := routetable.Exempt{TUN: "thinkpol0", Mark: routetable.Mark,
		Direct:    set(t, "198.51.100.0/24", "2001:db8:d0::/48", "203.0.113.7/32", "203.0.113.8/32", "2001:db8:7::7/128"),
		Upstreams: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.53:53"), netip.MustParseAddrPort("[2001:db8:53::1]:53")}}
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
	f          *fakeConfigurator
	events     chan struct{}
	mu         sync.Mutex
	applied    []routetable.Exempt
	after      []int
	failErr    error
	closed     bool
	closes     int
	closeErr   error           // what Close returns
	order      *[]string       // what was closed, in order
	watches    atomic.Int32    // subscriptions alive
	released   atomic.Int32    // subscriptions fully torn down
	subscribed []chan struct{} // closed when each Watch goroutine is listening
	watchErr   error           // what Watch returns; nil: it watches
}

func (g *fakeGuard) setWatchErr(err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.watchErr = err
}

func newFakeGuard(f *fakeConfigurator) *fakeGuard {
	return &fakeGuard{f: f, events: make(chan struct{})}
}

func (g *fakeGuard) Apply(ctx context.Context, e routetable.Exempt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
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
	ready := make(chan struct{})
	g.mu.Lock()
	if err := g.watchErr; err != nil {
		g.mu.Unlock()
		return nil, err
	}
	g.subscribed = append(g.subscribed, ready)
	g.mu.Unlock()
	g.watches.Add(1)
	go func() {
		close(ready)
		defer func() {
			g.watches.Add(-1)
			g.released.Add(1)
		}()
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
	g.closes++
	if g.order != nil {
		*g.order = append(*g.order, "guard")
	}
	return g.closeErr
}

// A Close that fails has let go of the owner lock all the same, so a
// second Close must not remove the guard: by then it may be the next
// run's.
func TestASecondCloseLeavesTheGuardAlone(t *testing.T) {
	f := &fakeConfigurator{events: make(chan struct{}), survey: up()}
	g := newFakeGuard(f)
	g.closeErr = errors.New("pfctl said no")
	e := routetable.OpenWithGuard(f, g, nil)
	if err := e.Enforce(context.Background(), routetable.Want{TUN: "thinkpol0"}); err != nil {
		t.Fatalf("Enforce: %v", err)
	}
	if err := e.Close(); !errors.Is(err, g.closeErr) || !f.closed {
		t.Fatalf("the first Close: %v, routes closed %v", err, f.closed)
	}
	if err := e.Close(); err != nil {
		t.Errorf("the second Close: %v", err)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closes != 1 {
		t.Errorf("the guard was closed %d times, want once", g.closes)
	}
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

	// Routes that fail leave the routes in place, and the guard is
	// applied for only what they and the failed Want both exempt: here
	// the failed Want's, which drops w's direct prefix.
	f.setFail(true)
	w2 := w
	w2.Direct = nil
	if err := e.Enforce(ctx, w2); err == nil {
		t.Fatal("Enforce succeeded on a failing configurator")
	}
	g.mu.Lock()
	last := g.applied[len(g.applied)-1]
	g.mu.Unlock()
	if !last.Equal(routetable.GuardFor(w2)) {
		t.Errorf("after the routes failed the guard was applied for %v, want none direct", last.Direct.Prefixes())
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
// deleted meanwhile is put back, for those routes but no wider than the
// Want that failed (a change that drops a prefix and adds another exempts
// only the one it keeps), and the status says how that went the whole
// time.
func TestTheGuardIsPutBackWhileTheRoutesFail(t *testing.T) {
	f := &fakeConfigurator{events: make(chan struct{}), survey: up()}
	g := newFakeGuard(f)
	e := routetable.OpenWithGuard(f, g, nil)
	defer func() { _ = e.Close() }()
	ctx := context.Background()
	w := routetable.Want{TUN: "thinkpol0", Direct: set(t, "2001:db8:d0::/48", "2001:db8:d2::/48")}
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
	w2.Direct = set(t, "2001:db8:d1::/48", "2001:db8:d2::/48")
	if err := e.Enforce(ctx, w2); err == nil {
		t.Fatal("Enforce succeeded on a failing configurator")
	}

	// The guard is deleted ("nft flush ruleset"): its Apply fails once,
	// which the status says, then works; each time for what both w,
	// whose routes are the ones in place, and w2 exempt.
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
	kept := routetable.GuardFor(routetable.Want{TUN: "thinkpol0", Direct: set(t, "2001:db8:d2::/48")})
	if !last.Equal(kept) {
		t.Errorf("the guard put back for %v, want what the routes in place and w2 both exempt: %v", last.Direct.Prefixes(), kept.Direct.Prefixes())
	}

	// The routes' own retry (every RetryAfter) checks the guard too,
	// without a guard event.
	n = g.count()
	eventually(t, "a route retry checking the guard", func() bool { return g.count() > n })
	f.setFail(false)
	eventually(t, "the routes back", func() bool { return e.Status().Enforced })
}

// lastGuard is the Exempt g was last given.
func lastGuard(g *fakeGuard) routetable.Exempt {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.applied[len(g.applied)-1]
}

// failingRig is an Enforcer whose routes went in for old and fail from
// then on: what the OS holds stays old's.
func failingRig(t *testing.T, old routetable.Want) (*routetable.Enforcer, *fakeConfigurator, *fakeGuard) {
	t.Helper()
	f := &fakeConfigurator{events: make(chan struct{}), survey: up()}
	g := newFakeGuard(f)
	e := routetable.OpenWithGuard(f, g, nil)
	t.Cleanup(func() { _ = e.Close() })
	if err := e.Enforce(t.Context(), old); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the check after Enforce", func() bool { return e.Status().Reapplies == 1 })
	f.setFail(true)
	return e, f, g
}

// checkRoutesStayed fails t unless the last routes that went in are
// old's, and nothing went in since the n-th Apply.
func checkRoutesStayed(t *testing.T, f *fakeConfigurator, n int, old routetable.Want) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if n == 0 || len(f.applies) != n {
		t.Errorf("%d route Applies, want %d (> 0)", len(f.applies), n)
		return
	}
	if got := routeStrings(f.applies[n-1]); !slices.Equal(got, routeStrings(routetable.Config(old, up()))) {
		t.Errorf("the last route Apply %v, want old's", got)
	}
}

// checkRepairs runs check after the routes' re-apply (after a failed
// Enforce, the watcher's retry RetryAfter later), then after the guard
// put back alone on its own Watch's signal.
func checkRepairs(t *testing.T, e *routetable.Enforcer, g *fakeGuard, check func(when string)) {
	t.Helper()
	r := e.Status().Reapplies
	eventually(t, "the routes' re-apply", func() bool { return e.Status().Reapplies > r })
	check("after the routes' re-apply")
	k := g.count()
	g.events <- struct{}{}
	eventually(t, "the guard put back after its Watch", func() bool { return g.count() > k })
	check("after the guard's Watch")
}

// A shrink that fails, and whose fallback to nothing direct fails too
// (the engine's order: the shrink, the fallback, then the new rules),
// leaves the old routes in place; the guard is the new, narrower set's,
// so IPv6 to the prefixes dropped is refused rather than sent direct.
// It stays so through the routes' retries and the guard's own repairs.
func TestAFailedShrinkNarrowsTheGuard(t *testing.T) {
	old := routetable.Want{TUN: "thinkpol0", Direct: set(t, "2001:db8:d0::/48", "2001:db8:d1::/48"),
		Bypass: []netip.Addr{netip.MustParseAddr("2001:db8:7::7")}}
	e, f, g := failingRig(t, old)
	n := f.count()
	shrunk := old
	shrunk.Direct = set(t, "2001:db8:d0::/48")
	none := old
	none.Direct = nil
	for i, w := range []routetable.Want{shrunk, none, shrunk} {
		if err := e.Enforce(t.Context(), w); err == nil {
			t.Fatal("Enforce succeeded on a failing configurator")
		}
		if i == 1 && !lastGuard(g).Equal(routetable.GuardFor(none)) {
			t.Errorf("after the failed fallback the guard exempts %v, want the endpoints alone", lastGuard(g).Direct.Prefixes())
		}
	}
	check := func(when string) {
		t.Helper()
		got := lastGuard(g)
		if !got.Equal(routetable.GuardFor(shrunk)) {
			t.Errorf("%s: the guard exempts %v, want the new set's %v", when, got.Direct.Prefixes(), routetable.GuardFor(shrunk).Direct.Prefixes())
		}
	}
	check("after the failed Enforces")
	if st := e.Status(); st.Enforced || st.Error == "" || !st.GuardEnforced {
		t.Errorf("status %+v: want the routes failing, the guard in place", st)
	}

	checkRepairs(t, e, g, check)
	checkRoutesStayed(t, f, n, old)
}

// A grow that fails leaves the old routes and their guard: never a guard
// wider than the routes in place, through retries and repairs alike.
func TestAFailedGrowHoldsTheGuardToTheRoutes(t *testing.T) {
	old := routetable.Want{TUN: "thinkpol0", Direct: set(t, "2001:db8:d0::/48")}
	e, f, g := failingRig(t, old)
	n := f.count()
	grown := old
	grown.Direct = set(t, "2001:db8:d0::/48", "2001:db8:d1::/48")
	if err := e.Enforce(t.Context(), grown); err == nil {
		t.Fatal("Enforce succeeded on a failing configurator")
	}
	check := func(when string) {
		t.Helper()
		got := lastGuard(g)
		if !got.Equal(routetable.GuardFor(old)) {
			t.Errorf("%s: the guard exempts %v, want the routes in place's %v", when, got.Direct.Prefixes(), routetable.GuardFor(old).Direct.Prefixes())
		}
	}
	check("after the failed Enforce")
	checkRepairs(t, e, g, check)
	checkRoutesStayed(t, f, n, old)
}

// Once a Want's routes go in after failures, the guard is that Want's,
// on its Apply and on the guard's own repairs alike: narrowed by a failed
// shrink, held by a failed grow, then widened back to the recovered
// set's.
func TestTheGuardFollowsTheRoutesBackAfterFailures(t *testing.T) {
	ep := netip.MustParseAddr("2001:db8:7::7")
	old := routetable.Want{TUN: "thinkpol0", Direct: set(t, "2001:db8:d0::/48", "2001:db8:d1::/48"), Bypass: []netip.Addr{ep}}
	e, f, g := failingRig(t, old)
	shrunk := old
	shrunk.Direct = set(t, "2001:db8:d0::/48")
	grown := old
	grown.Direct = set(t, "2001:db8:d0::/48", "2001:db8:d1::/48", "2001:db8:d2::/48")
	for _, w := range []routetable.Want{shrunk, grown} {
		if err := e.Enforce(t.Context(), w); err == nil {
			t.Fatal("Enforce succeeded on a failing configurator")
		}
	}

	// The shrink goes in: its guard, also after the guard's own Watch.
	f.setFail(false)
	if err := e.Enforce(t.Context(), shrunk); err != nil {
		t.Fatal(err)
	}
	checkGuard := func(when string, want routetable.Want) {
		t.Helper()
		if got := lastGuard(g); !got.Equal(routetable.GuardFor(want)) {
			t.Errorf("%s: the guard exempts %v, want %v", when, got.Direct.Prefixes(), routetable.GuardFor(want).Direct.Prefixes())
		}
	}
	checkRepairs(t, e, g, func(when string) { checkGuard("the shrink in, "+when, shrunk) })

	// A grow fails (the guard stays the shrink's), then goes in: the
	// guard widens to the grown set's, on its Apply and its repairs.
	f.setFail(true)
	if err := e.Enforce(t.Context(), grown); err == nil {
		t.Fatal("Enforce succeeded on a failing configurator")
	}
	checkGuard("the grow failing", shrunk)
	f.setFail(false)
	if err := e.Enforce(t.Context(), grown); err != nil {
		t.Fatal(err)
	}
	checkGuard("the grow in", grown)
	checkRepairs(t, e, g, func(when string) { checkGuard("the grow in, "+when, grown) })
	if st := e.Status(); !st.Enforced || !st.GuardEnforced {
		t.Errorf("status %+v: want the routes and the guard in place", st)
	}
}

// The guard for the routes in place and the rules is exactly what both
// exempt: never wider than either, and no narrower; TUN and Mark are the
// routes in place's.
func TestTheGuardIsTheIntersection(t *testing.T) {
	ep7, ep8 := netip.MustParseAddr("2001:db8:7::7"), netip.MustParseAddr("2001:db8:7::8")
	up1, up2 := netip.MustParseAddrPort("[2001:db8:53::1]:53"), netip.MustParseAddrPort("[2001:db8:53::2]:53")
	with := func(tun string, direct []string, eps []netip.Addr, ups []netip.AddrPort) routetable.Want {
		w := routetable.Want{TUN: tun, Bypass: eps, Upstreams: ups}
		if direct != nil {
			w.Direct = set(t, direct...)
		}
		return w
	}
	for _, c := range []struct {
		name       string
		held, want routetable.Want
	}{
		{"shrink", with("thinkpol0", []string{"2001:db8:d0::/48", "2001:db8:d1::/48"}, nil, nil), with("thinkpol0", []string{"2001:db8:d0::/48"}, nil, nil)},
		{"grow", with("thinkpol0", []string{"2001:db8:d0::/48"}, nil, nil), with("thinkpol0", []string{"2001:db8:d0::/48", "2001:db8:d1::/48"}, nil, nil)},
		{"partial overlap", with("thinkpol0", []string{"2001:db8::/32"}, nil, nil), with("thinkpol0", []string{"2001:db8:d0::/48", "2001:db9::/32"}, nil, nil)},
		{"partial overlap, the other way", with("thinkpol0", []string{"2001:db8:d0::/48", "2001:db9::/32"}, nil, nil), with("thinkpol0", []string{"2001:db8::/32"}, nil, nil)},
		{"to nothing", with("thinkpol0", []string{"2001:db8::/32", "198.51.100.0/24"}, []netip.Addr{ep7}, nil), with("thinkpol0", nil, []netip.Addr{ep7}, nil)},
		{"endpoints swapped", with("thinkpol0", nil, []netip.Addr{ep7}, nil), with("thinkpol0", nil, []netip.Addr{ep8}, nil)},
		{"endpoint inside a dropped prefix", with("thinkpol0", []string{"2001:db8:7::/48"}, nil, nil), with("thinkpol0", nil, []netip.Addr{ep7}, nil)},
		{"upstreams swapped", with("thinkpol0", nil, nil, []netip.AddrPort{up1}), with("thinkpol0", nil, nil, []netip.AddrPort{up2})},
		{"an upstream added", with("thinkpol0", nil, nil, []netip.AddrPort{up1}), with("thinkpol0", nil, nil, []netip.AddrPort{up2, up1})},
		{"another TUN", with("thinkpol0", []string{"2001:db8:d0::/48"}, nil, nil), with("thinkpol1", []string{"2001:db8:d0::/48"}, nil, nil)},
		{"same", with("thinkpol0", []string{"2001:db8:d0::/48"}, []netip.Addr{ep7}, []netip.AddrPort{up1}), with("thinkpol0", []string{"2001:db8:d0::/48"}, []netip.Addr{ep7}, []netip.AddrPort{up1})},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := routetable.GuardBetween(c.held, c.want)
			h, w := routetable.GuardFor(c.held), routetable.GuardFor(c.want)
			if both := h.Direct.Intersect(w.Direct); !got.Direct.Equal(both) {
				t.Errorf("exempts %v, want what both exempt: %v", got.Direct.Prefixes(), both.Prefixes())
			}
			var both []netip.AddrPort
			for _, ap := range h.Upstreams {
				if slices.Contains(w.Upstreams, ap) {
					both = append(both, ap)
				}
			}
			if !slices.Equal(got.Upstreams, both) {
				t.Errorf("upstreams %v, want those both exempt: %v", got.Upstreams, both)
			}
			if got.TUN != h.TUN || got.Mark != h.Mark {
				t.Errorf("TUN/Mark %q/%#x, want the routes in place's %q/%#x", got.TUN, got.Mark, h.TUN, h.Mark)
			}
			if c.held.Equal(c.want) && !got.Equal(h) {
				t.Errorf("held == want: %+v, want GuardFor(held)", got)
			}
		})
	}
}

// The upstreams both exempt come out sorted and once each, whatever
// order or repeats either side comes in.
func TestIntersectUpstreamsTakesThemInAnyOrder(t *testing.T) {
	up1, up2, up3 := netip.MustParseAddrPort("[2001:db8:53::1]:53"), netip.MustParseAddrPort("[2001:db8:53::2]:53"), netip.MustParseAddrPort("[2001:db8:53::3]:53")
	got := routetable.IntersectUpstreams([]netip.AddrPort{up2, up1, up2, up3}, []netip.AddrPort{up3, up2, up1})
	if want := []netip.AddrPort{up1, up2, up3}; !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
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
	eventually(t, "the Open watcher's subscription released", func() bool { return g.released.Load() >= 1 })
	eventually(t, "the new watcher subscribed", func() bool {
		g.mu.Lock()
		defer g.mu.Unlock()
		if len(g.subscribed) < 2 {
			return false
		}
		select {
		case <-g.subscribed[1]:
			return true
		default:
			return false
		}
	})
	eventually(t, "the new watcher's subscription released", func() bool {
		return g.released.Load() >= 2 && g.watches.Load() == 0
	})
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
	w.Upstreams = []netip.AddrPort{netip.MustParseAddrPort("[2001:db8:53::1]:53")}
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

// lockedBuffer is a test's log sink.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *lockedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *lockedBuffer) lines(s string) []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	var out []string
	for _, l := range strings.Split(w.b.String(), "\n") {
		if strings.Contains(l, s) {
			out = append(out, l)
		}
	}
	return out
}

// A guard that keeps failing is retried every RetryAfter, and every
// failure is warned, at most one line a minute, the failures silenced
// since the last line counted with it; a success resets the limit.
func TestGuardFailuresAreWarnedAtMostAMinuteApart(t *testing.T) {
	f := &fakeConfigurator{}
	g := newFakeGuard(f)
	g.setFail(errors.New("the guard's load was refused"))
	var buf lockedBuffer
	clock := &fakeClock{now: time.Unix(0, 0)}
	e := routetable.OpenWithClock(f, g, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), clock.read)
	defer func() { _ = e.Close() }()
	routetable.PauseWatching(e)
	apply := func() { routetable.GuardApply(t.Context(), e, routetable.Want{TUN: "thinkpol0"}) }
	warns := func() []string { return buf.lines("applying the leak guard failed") }

	// The first failure warns.
	apply()
	if n := len(warns()); n != 1 {
		t.Fatalf("%d warns after the first failure, want 1", n)
	}
	// Failures within the minute are counted, not warned.
	for range 5 {
		apply()
	}
	if n := len(warns()); n != 1 {
		t.Fatalf("%d warns within the minute, want 1", n)
	}
	// Past the minute, one line with the silenced count.
	clock.advance(routetable.WarnEvery)
	apply()
	if n := len(warns()); n != 2 {
		t.Fatalf("%d warns after a minute, want 2", n)
	}
	if !strings.Contains(warns()[1], "suppressed=5") {
		t.Errorf("the second warn doesn't count the silenced ones: %q", warns()[1])
	}
	// The limit starts again.
	apply()
	if n := len(warns()); n != 2 {
		t.Fatalf("%d warns right after, want 2", n)
	}
	// A success resets it: the next failure warns at once.
	g.setFail(nil)
	apply()
	g.setFail(errors.New("the guard's load was refused"))
	apply()
	if n := len(warns()); n != 3 {
		t.Fatalf("%d warns after a success in between, want 3", n)
	}
	if strings.Contains(warns()[2], "suppressed=") {
		t.Errorf("the warn after a success counts what wasn't silenced: %q", warns()[2])
	}
}

// fakeClock is a clock a test moves.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) read() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Every other failure retried every RetryAfter is warned through a limit
// of its own, as the guard's apply is: one line per WarnEvery, the
// failures held back counted with the next, a success starting over.
func TestRetriedFailuresAreWarnedAtMostOnceAMinute(t *testing.T) {
	for _, site := range []struct {
		name, warn, cleared string
		// fail makes the step fail with err, or succeed with nil.
		fail func(f *fakeConfigurator, g *fakeGuard, err error)
		step func(context.Context, *routetable.Enforcer)
	}{
		{"watching the routes", "watching routes failed", "watching routes again",
			func(f *fakeConfigurator, _ *fakeGuard, err error) { f.setWatchErr(err) }, routetable.Subscribe},
		{"watching the guard", "watching the leak guard failed", "watching the leak guard again",
			func(_ *fakeConfigurator, g *fakeGuard, err error) { g.setWatchErr(err) }, routetable.SubscribeGuard},
		{"putting the routes back", "putting it back failed", "the routes are in place again",
			func(f *fakeConfigurator, _ *fakeGuard, err error) { f.setFail(err != nil) }, routetable.Reapply},
	} {
		t.Run(site.name, func(t *testing.T) {
			ctx := t.Context()
			f := &fakeConfigurator{survey: up()}
			g := newFakeGuard(f)
			var buf lockedBuffer
			clock := &fakeClock{now: time.Unix(0, 0)}
			e := routetable.OpenWithClock(f, g, slog.New(slog.NewTextHandler(&buf, nil)), clock.read)
			defer func() { _ = e.Close() }()
			if err := e.Enforce(ctx, routetable.Want{TUN: "thinkpol0"}); err != nil {
				t.Fatal(err)
			}
			routetable.PauseWatching(e)
			warns := func() []string { return buf.lines(site.warn) }
			failure := errors.New("the OS said no")

			site.fail(f, g, failure)
			for range 6 {
				site.step(ctx, e)
			}
			if n := len(warns()); n != 1 {
				t.Fatalf("%d warns of 6 failures within the minute, want 1", n)
			}
			clock.advance(routetable.WarnEvery)
			site.step(ctx, e)
			if w := warns(); len(w) != 2 || !strings.Contains(w[1], "suppressed=5") {
				t.Fatalf("after the minute: %q, want a second warn with suppressed=5", w)
			}
			// A success says how many failures were held back since, once.
			site.step(ctx, e)
			site.fail(f, g, nil)
			site.step(ctx, e)
			site.step(ctx, e)
			if c := buf.lines(site.cleared); len(c) != 1 || !strings.Contains(c[0], "suppressed=1") {
				t.Fatalf("after a success: %q, want one line with suppressed=1", c)
			}
			site.fail(f, g, failure)
			site.step(ctx, e)
			if w := warns(); len(w) != 3 || strings.Contains(w[2], "suppressed=") {
				t.Fatalf("after a success: %q, want a third warn at once, nothing suppressed", w)
			}
		})
	}
}

// A guard Apply that failed because its context was cancelled is neither
// warned nor counted against the limit: the next real failure warns at
// once, with nothing suppressed. The guard is still retried.
func TestACancelledGuardApplyIsNotWarned(t *testing.T) {
	f := &fakeConfigurator{}
	g := newFakeGuard(f)
	var buf lockedBuffer
	clock := &fakeClock{now: time.Unix(0, 0)}
	e := routetable.OpenWithClock(f, g, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), clock.read)
	defer func() { _ = e.Close() }()
	warns := func() []string { return buf.lines("applying the leak guard failed") }
	w := routetable.Want{TUN: "thinkpol0"}

	routetable.PauseWatching(e)
	cancelled, cancel := context.WithCancel(t.Context())
	cancel()
	for range 3 {
		routetable.GuardApply(cancelled, e, w)
	}
	if n := len(warns()); n != 0 {
		t.Fatalf("%d warns of cancelled applies, want none", n)
	}
	if st := e.Status(); st.GuardEnforced || st.GuardError != routetable.ErrorGuard {
		t.Errorf("status after a cancelled apply: %+v", st)
	}
	g.setFail(errors.New("the guard's load was refused"))
	routetable.GuardApply(t.Context(), e, w)
	if w := warns(); len(w) != 1 || strings.Contains(w[0], "suppressed=") {
		t.Fatalf("the first real failure: %q, want one warn, nothing suppressed", w)
	}
}

// A success after failures whose warns were held back says how many
// there were, once; one after failures that were all warned says
// nothing.
func TestAGuardSuccessSaysHowManyFailuresWereHeldBack(t *testing.T) {
	f := &fakeConfigurator{}
	g := newFakeGuard(f)
	var buf lockedBuffer
	e := routetable.OpenWithClock(f, g, slog.New(slog.NewTextHandler(&buf, nil)), (&fakeClock{now: time.Unix(0, 0)}).read)
	defer func() { _ = e.Close() }()
	routetable.PauseWatching(e)
	apply := func() { routetable.GuardApply(t.Context(), e, routetable.Want{TUN: "thinkpol0"}) }
	cleared := func() []string { return buf.lines("the leak guard is in place again") }

	g.setFail(errors.New("the guard's load was refused"))
	for range 4 {
		apply() // one warned, three held back
	}
	g.setFail(nil)
	apply()
	apply()
	if c := cleared(); len(c) != 1 || !strings.Contains(c[0], "suppressed=3") || !strings.Contains(c[0], "level=INFO") {
		t.Fatalf("after the failures: %q, want one INFO line with suppressed=3", c)
	}
	g.setFail(errors.New("the guard's load was refused"))
	apply() // warned, nothing held back
	g.setFail(nil)
	apply()
	if c := cleared(); len(c) != 1 {
		t.Errorf("a success after a failure that was warned: %q, want nothing more", c)
	}
}

// guardWarnRig is an Enforcer whose guard fails as told (an empty
// message: succeeds), its watcher paused, on a clock the test moves.
func guardWarnRig(t *testing.T) (fail func(msg string), buf *lockedBuffer, clock *fakeClock) {
	t.Helper()
	f := &fakeConfigurator{}
	g := newFakeGuard(f)
	buf = &lockedBuffer{}
	clock = &fakeClock{now: time.Unix(0, 0)}
	e := routetable.OpenWithClock(f, g, slog.New(slog.NewTextHandler(buf, nil)), clock.read)
	t.Cleanup(func() { _ = e.Close() })
	routetable.PauseWatching(e)
	fail = func(msg string) {
		var err error
		if msg != "" {
			err = errors.New(msg)
		}
		g.setFail(err)
		routetable.GuardApply(t.Context(), e, routetable.Want{TUN: "thinkpol0"})
	}
	return fail, buf, clock
}

func guardWarns(buf *lockedBuffer) []string { return buf.lines("applying the leak guard failed") }

// A failure whose text changes on every retry never clears and never
// repeats a text: what one window held back is said with the next
// window's first warn, of whatever text.
func TestHeldBackTextsThatDontComeBackAreSaid(t *testing.T) {
	fail, buf, clock := guardWarnRig(t)
	const n = 2*routetable.WarnTexts + 1
	retry := 0
	failOnce := func() {
		fail(fmt.Sprintf("pf's table holds %d entries unlike the 999 loaded", retry))
		retry++
	}
	for range n {
		failOnce()
	}
	clock.advance(routetable.WarnEvery)
	failOnce()
	w := guardWarns(buf)
	want := fmt.Sprintf("suppressed_other=%d", n-routetable.WarnTexts)
	if len(w) != routetable.WarnTexts+1 || !strings.Contains(w[len(w)-1], want) || strings.Contains(w[len(w)-1], "suppressed=") {
		t.Fatalf("the next window's first warn: %q, want %s and no count of its own", w[len(w)-1], want)
	}
	failOnce()
	if w := guardWarns(buf); strings.Contains(w[len(w)-1], "suppressed_other") {
		t.Errorf("said twice: %q", w[len(w)-1])
	}
}

// Within a window each distinct (redacted) failure is warned once, so two
// that alternate warn once each; one that differs only in its addresses
// is the same failure. What was held back goes with the next warn of the
// same text.
func TestEachFailureIsWarnedOnceAWindow(t *testing.T) {
	fail, buf, clock := guardWarnRig(t)
	warns := func() []string { return guardWarns(buf) }
	const a = "pfctl -s rules: no answer within 15s"
	b := func(addr string) string {
		return `pf lists the guard's rule 4 as "pass out quick inet6 proto tcp from any to ` + addr + ` port = 53 keep state", not stateless`
	}
	fail(a)
	fail(b("2001:db8:53::1"))
	fail(a)
	fail(b("2001:db8:53::2"))
	fail(a)
	if w := warns(); len(w) != 2 || !strings.Contains(w[0], "no answer") || !strings.Contains(w[1], "rule 4") {
		t.Fatalf("warns %q, want A then B, once each", w)
	}
	clock.advance(routetable.WarnEvery)
	fail(b("2001:db8:53::3"))
	fail(a)
	w := warns()
	if len(w) != 4 || !strings.Contains(w[2], "rule 4") || !strings.Contains(w[2], "suppressed=1") ||
		!strings.Contains(w[3], "no answer") || !strings.Contains(w[3], "suppressed=2") {
		t.Fatalf("warns %q, want B with suppressed=1, then A with suppressed=2", w[2:])
	}
}

// A text that changes on every retry warns at most WarnTexts times a
// window; every failure held back is still counted when it clears.
func TestAWindowWarnsAtMostWarnTextsFailures(t *testing.T) {
	fail, buf, _ := guardWarnRig(t)
	const n = 2*routetable.WarnTexts + 1
	for i := range n {
		fail(fmt.Sprintf("pf's table holds %d entries unlike the 99 loaded", i))
	}
	if w := len(guardWarns(buf)); w != routetable.WarnTexts {
		t.Fatalf("%d warns of %d distinct failures, want %d", w, n, routetable.WarnTexts)
	}
	fail("")
	want := fmt.Sprintf("suppressed=%d", n-routetable.WarnTexts)
	if c := buf.lines("the leak guard is in place again"); len(c) != 1 || !strings.Contains(c[0], want) {
		t.Errorf("cleared: %q, want %s", c, want)
	}
}

// A subscription that fails because the watcher's context ended (Close or
// Enforce pausing it) isn't warned, and doesn't take the warn window; one
// that succeeds on an ended context recovers nothing, so it doesn't say
// so, and the held-back count waits for a live one.
func TestASubscriptionCutShortIsNotWarned(t *testing.T) {
	for _, site := range []struct {
		name, warn, cleared string
		fail                func(f *fakeConfigurator, g *fakeGuard, err error)
		step                func(context.Context, *routetable.Enforcer)
	}{
		{"routes", "watching routes failed", "watching routes again",
			func(f *fakeConfigurator, _ *fakeGuard, err error) { f.setWatchErr(err) }, routetable.Subscribe},
		{"guard", "watching the leak guard failed", "watching the leak guard again",
			func(_ *fakeConfigurator, g *fakeGuard, err error) { g.setWatchErr(err) }, routetable.SubscribeGuard},
	} {
		t.Run(site.name, func(t *testing.T) {
			f := &fakeConfigurator{survey: up()}
			g := newFakeGuard(f)
			var buf lockedBuffer
			e := routetable.OpenWithClock(f, g, slog.New(slog.NewTextHandler(&buf, nil)), (&fakeClock{now: time.Unix(0, 0)}).read)
			defer func() { _ = e.Close() }()
			routetable.PauseWatching(e)
			stopped, cancel := context.WithCancel(t.Context())
			cancel()
			site.fail(f, g, context.Canceled)
			site.step(stopped, e)
			if w := buf.lines(site.warn); len(w) != 0 {
				t.Fatalf("warned %q for a stopped watcher", w)
			}
			site.fail(f, g, errors.New("the OS said no"))
			site.step(t.Context(), e)
			site.step(t.Context(), e)
			if w := buf.lines(site.warn); len(w) != 1 || strings.Contains(w[0], "suppressed=") {
				t.Fatalf("the first real failures: %q, want one warn, nothing suppressed", w)
			}
			site.fail(f, g, nil) // the fake's Watch succeeds whatever its context
			site.step(stopped, e)
			if c := buf.lines(site.cleared); len(c) != 0 {
				t.Fatalf("a stopped watcher's subscription said %q", c)
			}
			site.step(t.Context(), e)
			if c := buf.lines(site.cleared); len(c) != 1 || !strings.Contains(c[0], "suppressed=1") {
				t.Fatalf("the live subscription said %q, want suppressed=1", c)
			}
		})
	}
}

// A successful Enforce ends a re-apply failure: the next re-apply failure,
// within a minute of the old one's warn, is warned at once.
func TestAnEnforceEndsAReapplyFailure(t *testing.T) {
	f := &fakeConfigurator{survey: up()}
	var buf lockedBuffer
	e := routetable.OpenWithClock(f, nil, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), (&fakeClock{now: time.Unix(0, 0)}).read)
	defer func() { _ = e.Close() }()
	w := routetable.Want{TUN: "thinkpol0"}
	if err := e.Enforce(t.Context(), w); err != nil {
		t.Fatal(err)
	}
	routetable.PauseWatching(e)
	warns := func() []string { return buf.lines("putting it back failed") }
	f.setFail(true)
	routetable.Reapply(t.Context(), e)
	f.setFail(false)
	if err := e.Enforce(t.Context(), w); err != nil {
		t.Fatal(err)
	}
	routetable.PauseWatching(e) // before its check re-applies, a debounce later
	f.setFail(true)
	routetable.Reapply(t.Context(), e)
	if w := warns(); len(w) != 2 {
		t.Fatalf("warns %q, want the new failure warned at once", w)
	}
}

// A re-apply that finds the OS can't hold the table at all is warned
// whatever the limit holds back, with the count it held back: nothing is
// retried after it.
func TestATerminalReapplyFailureIsAlwaysWarned(t *testing.T) {
	f := &fakeConfigurator{survey: up()}
	var buf lockedBuffer
	e := routetable.OpenWithClock(f, nil, slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn})), (&fakeClock{now: time.Unix(0, 0)}).read)
	defer func() { _ = e.Close() }()
	if err := e.Enforce(t.Context(), routetable.Want{TUN: "thinkpol0"}); err != nil {
		t.Fatal(err)
	}
	routetable.PauseWatching(e)
	// The same text as the terminal one, so only its kind tells them apart.
	f.setFailErr(errors.New("rules: " + errors.ErrUnsupported.Error()))
	routetable.Reapply(t.Context(), e)
	routetable.Reapply(t.Context(), e) // held back
	f.setFailErr(fmt.Errorf("rules: %w", errors.ErrUnsupported))
	routetable.Reapply(t.Context(), e)
	if l := buf.lines("level=WARN"); len(l) != 2 || !strings.Contains(l[1], "can't hold the route table") || !strings.Contains(l[1], "suppressed=1") {
		t.Fatalf("warns %q, want the terminal failure warned too, with the one held back", l)
	}
}

// The guard turning out unsupported is warned with the failures its limit
// held back before: nothing retries the guard after it.
func TestAnUnsupportedGuardSaysWhatWasHeldBack(t *testing.T) {
	f := &fakeConfigurator{}
	g := newFakeGuard(f)
	var buf lockedBuffer
	e := routetable.OpenWithClock(f, g, slog.New(slog.NewTextHandler(&buf, nil)), (&fakeClock{now: time.Unix(0, 0)}).read)
	defer func() { _ = e.Close() }()
	routetable.PauseWatching(e)
	failWith := func(err error) {
		g.setFail(err)
		routetable.GuardApply(t.Context(), e, routetable.Want{TUN: "thinkpol0"})
	}
	failWith(errors.New("pfctl -s rules: no answer within 15s"))
	failWith(errors.New("pfctl -s rules: no answer within 15s")) // held back
	failWith(fmt.Errorf("%w: pf's main ruleset has no anchor", routetable.ErrGuardUnsupported))
	if l := buf.lines("can't hold the leak guard"); len(l) != 1 || !strings.Contains(l[0], "suppressed=1") {
		t.Fatalf("logged %q, want the unsupported warn with suppressed=1", l)
	}
}
