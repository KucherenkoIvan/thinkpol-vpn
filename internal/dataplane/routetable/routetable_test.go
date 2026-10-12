package routetable_test

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

func set(t testing.TB, prefixes ...string) *lists.Set {
	t.Helper()
	var b lists.Builder
	for _, p := range prefixes {
		if err := b.AddPrefix(netip.MustParsePrefix(p)); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := b.Build()
	return s
}

func routeStrings(cfg netcfg.Config) []string {
	var out []string
	for _, r := range cfg.Routes {
		out = append(out, r.String())
	}
	return out
}

func TestConfigLayout(t *testing.T) {
	w := routetable.Want{
		TUN:    "thinkpol0",
		Direct: set(t, "10.0.0.0/8", "198.51.100.0/24", "fc00::/7"),
		// Endpoints: one inside a direct prefix, one adjacent to one (the
		// throws merge), one IPv4-mapped, one twice.
		Bypass: []netip.Addr{
			netip.MustParseAddr("10.1.2.3"),
			netip.MustParseAddr("198.51.101.0"),
			netip.MustParseAddr("::ffff:203.0.113.9"),
			netip.MustParseAddr("2001:db8::1"),
			netip.MustParseAddr("2001:db8::1"),
		},
		IPv6: true,
	}
	cfg := routetable.Config(w)
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"0.0.0.0/0 dev thinkpol0 table 29808",
		"::/0 dev thinkpol0 table 29808",
		"unreachable ::/0 metric 2048 table 29808",
		"throw 10.0.0.0/8 table 29808",
		"throw 198.51.100.0/24 table 29808",
		"throw 198.51.101.0/32 table 29808",
		"throw 203.0.113.9/32 table 29808",
		"throw 2001:db8::1/128 table 29808",
		"throw fc00::/7 table 29808",
	}
	if got := routeStrings(cfg); !slices.Equal(got, want) {
		t.Errorf("routes:\n got %q\nwant %q", got, want)
	}
	if w.Routes() != len(want) {
		t.Errorf("Routes() = %d, want %d", w.Routes(), len(want))
	}
	wantRules := []netcfg.Rule{
		{Family: netcfg.IPv4, Priority: 5300, SuppressDefaultRoutes: true},
		{Family: netcfg.IPv4, Priority: 5301, Table: routetable.Table, Mark: routetable.Mark, Invert: true},
		{Family: netcfg.IPv6, Priority: 5300, SuppressDefaultRoutes: true},
		{Family: netcfg.IPv6, Priority: 5301, Table: routetable.Table, Mark: routetable.Mark, Invert: true},
	}
	if !slices.Equal(cfg.Rules, wantRules) {
		t.Errorf("rules:\n got %v\nwant %v", cfg.Rules, wantRules)
	}
}

// Without IPv6 in the TUN, IPv6 meets only the unreachable default (and
// the throws): it is dropped, never sent around the tunnel.
func TestConfigWithoutIPv6(t *testing.T) {
	cfg := routetable.Config(routetable.Want{TUN: "thinkpol0", Direct: set(t, "fe80::/10")})
	want := []string{
		"0.0.0.0/0 dev thinkpol0 table 29808",
		"unreachable ::/0 metric 2048 table 29808",
		"throw fe80::/10 table 29808",
	}
	if got := routeStrings(cfg); !slices.Equal(got, want) {
		t.Errorf("routes:\n got %q\nwant %q", got, want)
	}
}

func TestWantEqual(t *testing.T) {
	a := routetable.Want{TUN: "t", Direct: set(t, "10.0.0.0/8"), Bypass: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")}}
	b := a
	b.Direct = set(t, "10.0.0.0/9", "10.128.0.0/9")
	b.Bypass = []netip.Addr{netip.MustParseAddr("192.0.2.2"), netip.MustParseAddr("::ffff:192.0.2.1")}
	if !a.Equal(b) {
		t.Error("the same routes compare unequal")
	}
	for name, mod := range map[string]func(*routetable.Want){
		"tun":    func(w *routetable.Want) { w.TUN = "u" },
		"ipv6":   func(w *routetable.Want) { w.IPv6 = true },
		"direct": func(w *routetable.Want) { w.Direct = nil },
		"bypass": func(w *routetable.Want) { w.Bypass = w.Bypass[:1] },
	} {
		c := a
		mod(&c)
		if a.Equal(c) {
			t.Errorf("%s: unequal wants compare equal", name)
		}
	}
}

// fakeConfigurator records Applies and lets the test signal Watch.
type fakeConfigurator struct {
	mu      sync.Mutex
	applies []netcfg.Config
	fail    bool
	closed  bool
	events  chan struct{}
}

func (f *fakeConfigurator) Apply(_ context.Context, cfg netcfg.Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail {
		return errors.New("the kernel said no")
	}
	f.applies = append(f.applies, cfg)
	return nil
}

func (f *fakeConfigurator) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.applies)
}

func (f *fakeConfigurator) DefaultRoute(context.Context, netcfg.Family) (netcfg.Route, error) {
	return netcfg.Route{}, netcfg.ErrNoDefaultRoute
}

func (f *fakeConfigurator) Watch(ctx context.Context) (<-chan struct{}, error) {
	out := make(chan struct{})
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case <-f.events:
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

func (f *fakeConfigurator) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func TestEnforcerAppliesChangesAndReappliesOnEvents(t *testing.T) {
	f := &fakeConfigurator{events: make(chan struct{})}
	e := routetable.Open(f, nil)
	ctx := context.Background()
	w := routetable.Want{TUN: "thinkpol0", Direct: set(t, "10.0.0.0/8")}
	if err := e.Enforce(ctx, w); err != nil {
		t.Fatal(err)
	}
	if err := e.Enforce(ctx, w); err != nil {
		t.Fatal(err)
	}
	if n := f.count(); n != 1 {
		t.Fatalf("%d Applies for one Want twice, want 1", n)
	}
	if st := e.Status(); st.Routes != 3 {
		t.Errorf("status routes %d, want 3", st.Routes)
	}
	// A burst of events is one re-Apply of the same config.
	for range 5 {
		f.events <- struct{}{}
	}
	deadline := time.Now().Add(3 * time.Second)
	for f.count() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(400 * time.Millisecond)
	if n := f.count(); n != 2 {
		t.Fatalf("%d Applies after a burst of events, want 2", n)
	}
	if st := e.Status(); st.Reapplies != 1 {
		t.Errorf("reapplies %d, want 1", st.Reapplies)
	}
	f.mu.Lock()
	same := slices.Equal(routeStrings(f.applies[0]), routeStrings(f.applies[1]))
	f.mu.Unlock()
	if !same {
		t.Error("the re-Apply applied another config")
	}

	// A failed Enforce keeps what was in place, and the next one tries
	// again.
	f.mu.Lock()
	f.fail = true
	f.mu.Unlock()
	w2 := w
	w2.Direct = nil
	if err := e.Enforce(ctx, w2); err == nil {
		t.Fatal("Enforce succeeded on a failing configurator")
	}
	f.mu.Lock()
	f.fail = false
	f.mu.Unlock()
	if err := e.Enforce(ctx, w2); err != nil {
		t.Fatal(err)
	}
	if n := f.count(); n != 3 {
		t.Errorf("%d Applies, want 3", n)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if !f.closed {
		t.Error("Close didn't close the configurator")
	}
	if err := e.Enforce(ctx, routetable.Want{}); err == nil {
		t.Error("Enforce without a TUN succeeded")
	}
}

// All of IPv4 direct (no overlay network claiming part of it) is a throw
// default, not a second default route of the same identity.
func TestConfigWithEverythingDirect(t *testing.T) {
	cfg := routetable.Config(routetable.Want{TUN: "thinkpol0", Direct: set(t, "0.0.0.0/0"), IPv6: true})
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"::/0 dev thinkpol0 table 29808",
		"unreachable ::/0 metric 2048 table 29808",
		"throw 0.0.0.0/0 table 29808",
	}
	if got := routeStrings(cfg); !slices.Equal(got, want) {
		t.Errorf("routes:\n got %q\nwant %q", got, want)
	}
}
