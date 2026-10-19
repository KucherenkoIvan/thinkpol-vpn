package dataplane_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/rules"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// fakeRouteTable records what the engine enforces; failing makes the next
// calls fail.
type fakeRouteTable struct {
	mu      sync.Mutex
	calls   []routetable.Want
	failing int
	closed  bool
	// hold, if set, keeps Enforce until it is closed; entered hears
	// when an Enforce is held.
	hold, entered chan struct{}
}

var errKernel = errors.New("the kernel said no")

func (f *fakeRouteTable) Enforce(_ context.Context, w routetable.Want) error {
	f.mu.Lock()
	hold, entered := f.hold, f.entered
	f.mu.Unlock()
	if hold != nil {
		entered <- struct{}{}
		<-hold
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, w)
	if f.failing > 0 {
		f.failing--
		return errKernel
	}
	return nil
}

func (f *fakeRouteTable) Status() routetable.Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return routetable.Status{Enforced: f.failing == 0, Routes: len(f.calls)}
}

func (f *fakeRouteTable) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// since returns the calls after the first n, and how many there are.
func (f *fakeRouteTable) since(n int) ([]routetable.Want, int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.calls[n:]), len(f.calls)
}

// directOf is the local ranges and prefixes, less the space's overlay
// networks (decided before any rule).
func directOf(t *testing.T, prefixes ...string) *lists.Set {
	t.Helper()
	var b, overlay lists.Builder
	b.AddSet(lists.Local())
	for _, p := range prefixes {
		if err := b.AddPrefix(netip.MustParsePrefix(p)); err != nil {
			t.Fatal(err)
		}
	}
	_ = overlay.AddPrefix(space4)
	_ = overlay.AddPrefix(space6)
	s, _ := b.Build()
	o, _ := overlay.Build()
	return s.Minus(o)
}

// The OS routing table gets the rules' direct set and the links'
// endpoints; a direct set that shrinks is taken out before the router
// changes and only then put back as the new set, and a removal that fails
// falls back to nothing direct.
func TestRouteTableFollowsTheRules(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, _ := m0()
	withChain(t, a, s, "local -> direct", "cidr:198.51.100.0/24 -> direct", "default -> chain:nl")
	a.section.Presets = netmap.RulePresets{Chain: "nl"}
	rt := &fakeRouteTable{}
	a.routes = rt
	s.start(t, net)
	a.start(t, net)

	spaceDirect := directOf(t, "198.51.100.0/24")
	calls, n := rt.since(0)
	if len(calls) != 1 {
		t.Fatalf("%d Enforce calls for the first Apply, want 1", len(calls))
	}
	w := calls[0]
	if w.TUN != "loopbackTun1" || !w.IPv6 || !w.Direct.Equal(spaceDirect) ||
		!slices.Contains(w.Overlay, space4) || !slices.Contains(w.Overlay, space6) || len(w.Overlay) != 2 ||
		!slices.Equal(w.Bypass, []netip.Addr{s.listen.Addr()}) {
		t.Fatalf("enforced %+v", w)
	}
	if st := a.engine.Status().RouteTable; !st.Enforced || st.Routes != 1 {
		t.Errorf("status %+v", st)
	}

	// "Everything": only the local ranges go direct. The country's routes
	// go first, then the router changes, then the (same) final set.
	if err := a.engine.SetRules(rules.Local{Preset: rules.PresetEverything}); err != nil {
		t.Fatal(err)
	}
	calls, n = rt.since(n)
	if len(calls) != 2 || !calls[0].Direct.Equal(directOf(t)) || !calls[1].Direct.Equal(directOf(t)) {
		t.Fatalf("switching to everything enforced %d wants: %v", len(calls), calls)
	}
	if got := routeOf(t, a, netip.MustParseAddr("198.51.100.7")); got != exitOf(s) {
		t.Errorf("198.51.100.7 after switching: %s", got)
	}

	// Back to the space's rules: growing needs no removal first.
	if err := a.engine.SetRules(rules.Local{}); err != nil {
		t.Fatal(err)
	}
	calls, n = rt.since(n)
	if len(calls) != 1 || !calls[0].Direct.Equal(spaceDirect) {
		t.Fatalf("switching back enforced %v", calls)
	}

	// The removal fails: nothing goes direct, until the final set is in.
	rt.mu.Lock()
	rt.failing = 1
	rt.mu.Unlock()
	if err := a.engine.SetRules(rules.Local{Preset: rules.PresetEverything}); err != nil {
		t.Fatal(err)
	}
	calls, n = rt.since(n)
	if len(calls) != 3 || calls[1].Direct != nil || !calls[2].Direct.Equal(directOf(t)) {
		t.Fatalf("a failed removal enforced %v", calls)
	}

	// The final set fails: Apply says so, by step.
	rt.mu.Lock()
	rt.failing = 1
	rt.mu.Unlock()
	if err := a.engine.SetRules(rules.Local{}); !errors.Is(err, errKernel) || !errors.Is(err, dataplane.ErrRouteTableNotEnforced) {
		t.Fatalf("SetRules with the route table failing: %v", err)
	}
	a.section.Rules = a.section.Rules[1:] // local no longer direct
	rt.mu.Lock()
	rt.failing = 3
	rt.mu.Unlock()
	if err := a.engine.Apply(context.Background(), a.section); !errors.Is(err, dataplane.ErrRouteTableNotEnforced) {
		t.Fatalf("Apply with the route table failing: %v", err)
	}
	if st := a.engine.Status(); st.LastApplyError != dataplane.StepRouteTable {
		t.Errorf("last apply error %q, want %q", st.LastApplyError, dataplane.StepRouteTable)
	}
	_, _ = rt.since(n)
	if err := a.engine.Close(); err != nil {
		t.Fatal(err)
	}
	if !rt.closed {
		t.Error("Close left the route table")
	}
}

// Status doesn't wait while the OS routing table changes (seconds at a
// country's size).
func TestStatusDoesNotWaitForTheRouteTable(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, _ := m0()
	withChain(t, a, s, "cidr:198.51.100.0/24 -> direct", "default -> chain:nl")
	a.section.Presets = netmap.RulePresets{Chain: "nl"}
	rt := &fakeRouteTable{}
	a.routes = rt
	s.start(t, net)
	a.start(t, net)
	hold := make(chan struct{})
	rt.mu.Lock()
	rt.hold, rt.entered = hold, make(chan struct{}, 4)
	rt.mu.Unlock()
	done := make(chan error, 1)
	go func() { done <- a.engine.SetRules(rules.Local{Preset: rules.PresetEverything}) }()
	<-rt.entered
	status := make(chan struct{})
	go func() { _ = a.engine.Status(); close(status) }()
	select {
	case <-status:
	case <-time.After(5 * time.Second):
		t.Fatal("Status waited for the route table")
	}
	select {
	case err := <-done:
		t.Fatalf("SetRules returned while its route table was held: %v", err)
	default:
	}
	close(hold)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

// The resolver's direct upstreams reach the route table (macOS gives them
// routes scoped to the physical interface): kept from before the first
// Apply, re-enforced when they change, and not when they don't.
func TestDirectUpstreamsReachTheRouteTable(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, _ := m0()
	rt := &fakeRouteTable{}
	a.routes = rt
	s.start(t, net)
	a.start(t, net)
	ctx := context.Background()
	up := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.53:53"), netip.MustParseAddrPort("[2001:db8::53]:53")}
	_, n := rt.since(0)
	if err := a.engine.SetDirectUpstreams(ctx, up); err != nil {
		t.Fatal(err)
	}
	calls, n := rt.since(n)
	want := []netip.AddrPort{up[0], up[1]}
	slices.SortFunc(want, func(x, y netip.AddrPort) int { return x.Compare(y) })
	if len(calls) != 1 || !slices.Equal(calls[0].Upstreams, want) || !slices.Equal(calls[0].Bypass, []netip.Addr{s.listen.Addr()}) {
		t.Fatalf("enforced %+v", calls)
	}
	if err := a.engine.SetDirectUpstreams(ctx, []netip.AddrPort{up[1], up[0], up[0]}); err != nil {
		t.Fatal(err)
	}
	if calls, _ := rt.since(n); len(calls) != 0 {
		t.Errorf("the same upstreams enforced again: %v", calls)
	}
	// A map applied later keeps them.
	a.apply(t)
	if calls, _ := rt.since(n); len(calls) == 0 || !slices.Equal(calls[len(calls)-1].Upstreams, want) {
		t.Errorf("after an Apply: %+v", calls)
	}
}
