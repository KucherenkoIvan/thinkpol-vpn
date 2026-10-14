package routetable_test

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// The guard lets out around the tunnel exactly what the table throws,
// and the links' marked sockets.
func TestGuardForIsWhatTheTableThrows(t *testing.T) {
	w := routetable.Want{
		TUN:     "thinkpol0",
		Overlay: overlay,
		Direct:  set(t, "198.51.100.0/24", "2001:db8:d0::/48"),
		Bypass:  []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8:7::7"), netip.MustParseAddr("::ffff:203.0.113.8"), {}},
		IPv6:    true,
	}
	want := firewall.Exempt{TUN: "thinkpol0", Mark: routetable.Mark,
		Direct: set(t, "198.51.100.0/24", "2001:db8:d0::/48", "203.0.113.7/32", "203.0.113.8/32", "2001:db8:7::7/128")}
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
// the configurator had seen by then.
type fakeGuard struct {
	f       *fakeConfigurator
	mu      sync.Mutex
	applied []firewall.Exempt
	after   []int
	fail    bool
	closed  bool
}

func (g *fakeGuard) Apply(_ context.Context, e firewall.Exempt) error {
	n := g.f.count()
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.fail {
		return errors.New("nftables said no")
	}
	g.applied = append(g.applied, e)
	g.after = append(g.after, n)
	return nil
}

func (g *fakeGuard) count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.applied)
}

func (g *fakeGuard) setFail(fail bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fail = fail
}

func (g *fakeGuard) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.closed = true
	return nil
}

func TestEnforcerAppliesTheGuardWithTheRoutes(t *testing.T) {
	f := &fakeConfigurator{events: make(chan struct{}), survey: up()}
	g := &fakeGuard{f: f}
	e := routetable.OpenWithGuard(f, g, nil)
	ctx := context.Background()
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
	// Every re-Apply checks the guard too (someone may have removed it).
	eventually(t, "the check after Enforce", func() bool { return e.Status().Reapplies == 1 })
	if n := g.count(); n != 2 {
		t.Errorf("%d guard Applies after the re-Apply, want 2", n)
	}

	// Routes that fail leave the guard as it was.
	f.setFail(true)
	w2 := w
	w2.Direct = nil
	if err := e.Enforce(ctx, w2); err == nil {
		t.Fatal("Enforce succeeded on a failing configurator")
	}
	if n := g.count(); n != 2 {
		t.Errorf("the guard was applied after the routes failed (%d Applies)", n)
	}
	f.setFail(false)

	// A guard that fails fails the Enforce, says so, and is retried.
	g.setFail(true)
	if err := e.Enforce(ctx, w2); err == nil {
		t.Fatal("Enforce succeeded with a failing guard")
	}
	if st := e.Status(); st.Enforced || st.Error != routetable.ErrorGuard {
		t.Errorf("status with a failing guard: %+v", st)
	}
	g.setFail(false)
	eventually(t, "the guard retried within RetryAfter", func() bool { return e.Status().Enforced })
	g.mu.Lock()
	last := g.applied[len(g.applied)-1]
	g.mu.Unlock()
	if !last.Equal(routetable.GuardFor(w2)) {
		t.Errorf("the retry applied %+v, want %+v", last, routetable.GuardFor(w2))
	}

	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if !g.closed || !f.closed {
		t.Errorf("Close: guard closed %v, configurator closed %v", g.closed, f.closed)
	}
}
