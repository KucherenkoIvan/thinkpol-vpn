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
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/rules"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// fakeRouteTable records what the engine enforces; failing makes the next
// calls fail.
type fakeRouteTable struct {
	mu      sync.Mutex
	calls   []dataplane.RouteTableWant
	failing int
	closed  bool
	// hold, if set, keeps Enforce until it is closed; entered hears
	// when an Enforce is held.
	hold, entered chan struct{}
}

var errKernel = errors.New("the kernel said no")

func (f *fakeRouteTable) Enforce(_ context.Context, w dataplane.RouteTableWant) error {
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

func (f *fakeRouteTable) Status() dataplane.RouteTableStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	return dataplane.RouteTableStatus{Enforced: f.failing == 0, Routes: len(f.calls)}
}

func (f *fakeRouteTable) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

// since returns the calls after the first n, and how many there are.
func (f *fakeRouteTable) since(n int) ([]dataplane.RouteTableWant, int) {
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
	if err := a.engine.SetRules(rules.Local{}); !errors.Is(err, errKernel) {
		t.Fatalf("SetRules with the route table failing: %v", err)
	}
	a.section.Rules = a.section.Rules[1:] // local no longer direct
	rt.mu.Lock()
	rt.failing = 3
	rt.mu.Unlock()
	if err := a.engine.Apply(context.Background(), a.section); !errors.Is(err, errKernel) {
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

// The OS table's direct routes shrink while the router still routes the
// old rules, and grow once it routes the new ones: a destination the
// rules stop sending direct never leaves around the tunnel meanwhile.
func TestDirectRoutesShrinkBeforeTheRouterChangesAndGrowAfter(t *testing.T) {
	net := memory.NewNetwork(memory.Datagram)
	a, s, _ := m0()
	withChain(t, a, s, "local -> direct", "cidr:198.51.100.0/24 -> direct", "default -> chain:nl")
	a.section.Presets = netmap.RulePresets{Chain: "nl"}
	rt := &fakeRouteTable{}
	a.routes = rt
	s.start(t, net)
	a.start(t, net)
	dst := netip.MustParseAddr("198.51.100.7")
	// set switches the rules to l, holding each Enforce while it checks
	// where the router sends dst: during, one per Enforce.
	set := func(l rules.Local, during ...string) {
		t.Helper()
		hold, entered := make(chan struct{}), make(chan struct{}, 8)
		rt.mu.Lock()
		rt.hold, rt.entered = hold, entered
		rt.mu.Unlock()
		done := make(chan error, 1)
		go func() { done <- a.engine.SetRules(l) }()
		defer func() {
			close(hold) // whatever else it enforces goes through
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			if n := len(entered); n > 0 {
				t.Errorf("%v: %d more Enforce calls than %d", l.Preset, n, len(during))
			}
		}()
		for i, want := range during {
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				t.Errorf("%v: %d Enforce calls, want %d", l.Preset, i, len(during))
				return
			}
			if got := routeOf(t, a, dst); got != want {
				t.Errorf("%v, Enforce %d: the router sends %v %s, want %s", l.Preset, i+1, dst, got, want)
			}
			hold <- struct{}{}
		}
	}
	// Shrinking: still direct while the country's routes go, then the
	// chain's exit as the final set goes in.
	set(rules.Local{Preset: rules.PresetEverything}, sentDirect, exitOf(s))
	// Growing: direct before the country's routes come back.
	set(rules.Local{}, sentDirect)
}
