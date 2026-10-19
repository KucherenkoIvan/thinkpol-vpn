package agent

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// The resolver's direct upstreams reach the route table (macOS gives them
// routes scoped to the physical interface): kept from before the first
// Enforce, re-enforced with what is in place when they change, not when
// they don't, and carried by every Enforce after.
func TestDirectUpstreamsReachTheRouteTable(t *testing.T) {
	table := &wantsTable{}
	rt := newRouteTable(table)
	ctx := context.Background()
	calls := func() []routetable.Want {
		table.mu.Lock()
		defer table.mu.Unlock()
		return slices.Clone(table.wants)
	}
	up := []netip.AddrPort{netip.MustParseAddrPort("203.0.113.53:53"), netip.MustParseAddrPort("[2001:db8::53]:53")}
	want := slices.Clone(up)
	slices.SortFunc(want, func(x, y netip.AddrPort) int { return x.Compare(y) })

	if err := rt.SetDirectUpstreams(ctx, up[:1]); err != nil {
		t.Fatal(err)
	}
	if c := calls(); len(c) != 0 {
		t.Fatalf("upstreams before the first Enforce enforced %+v", c)
	}
	endpoint := netip.MustParseAddr("192.0.2.7")
	w := dataplane.RouteTableWant{TUN: "tun0", Bypass: []netip.Addr{endpoint}, IPv6: true}
	if err := rt.Enforce(ctx, w); err != nil {
		t.Fatal(err)
	}
	if c := calls(); len(c) != 1 || !slices.Equal(c[0].Upstreams, up[:1]) {
		t.Fatalf("the first Enforce enforced %+v", c)
	}

	if err := rt.SetDirectUpstreams(ctx, up); err != nil {
		t.Fatal(err)
	}
	c := calls()
	if len(c) != 2 || !slices.Equal(c[1].Upstreams, want) || c[1].TUN != "tun0" || !c[1].IPv6 ||
		!slices.Equal(c[1].Bypass, []netip.Addr{endpoint}) {
		t.Fatalf("new upstreams enforced %+v", c[1:])
	}
	if err := rt.SetDirectUpstreams(ctx, []netip.AddrPort{up[1], up[0], up[0]}); err != nil {
		t.Fatal(err)
	}
	if c := calls(); len(c) != 2 {
		t.Errorf("the same upstreams enforced again: %+v", c[2:])
	}
	w.Bypass = nil
	if err := rt.Enforce(ctx, w); err != nil {
		t.Fatal(err)
	}
	if c := calls(); len(c) != 3 || !slices.Equal(c[2].Upstreams, want) || len(c[2].Bypass) != 0 {
		t.Errorf("a later Enforce enforced %+v", c[2:])
	}

	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	if err := rt.SetDirectUpstreams(ctx, up[:1]); !errors.Is(err, dataplane.ErrEngineClosed) {
		t.Errorf("SetDirectUpstreams after Close: %v", err)
	}
}

// The resolver gets the engine's routes for names and addresses as they
// are, and none where the engine gives none (every name direct).
func TestTheResolverGetsTheEnginesRoutes(t *testing.T) {
	via := []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	if c := dnsConfig(dataplane.ResolverConfig{Zone: "space.internal"}); c.Route != nil || c.RouteAddr != nil || c.Zone != "space.internal" {
		t.Fatalf("without routes: %+v", c)
	}
	routes := map[string]dataplane.NameRoute{
		"direct.example": {Kind: dataplane.ResolveDirect},
		"tunnel.example": {Kind: dataplane.ResolveTunnel, Via: via},
		"block.example":  {Kind: dataplane.ResolveBlock},
	}
	c := dnsConfig(dataplane.ResolverConfig{
		Route: func(name string) dataplane.NameRoute { return routes[name] },
		RouteAddr: func(netip.Addr) dataplane.NameRoute {
			return dataplane.NameRoute{Kind: dataplane.ResolveTunnel, Via: via}
		},
	})
	for name, want := range map[string]dns.Route{
		"direct.example": {Kind: dns.RouteDirect},
		"tunnel.example": {Kind: dns.RouteTunnel, Via: via},
		"block.example":  {Kind: dns.RouteBlock},
		"other.example":  {Kind: dns.RouteBlock}, // no kind: fails closed
	} {
		if got := c.Route(name); got.Kind != want.Kind || !slices.Equal(got.Via, want.Via) {
			t.Errorf("%s: %+v, want %+v", name, got, want)
		}
	}
	if got := c.RouteAddr(netip.MustParseAddr("192.0.2.1")); got.Kind != dns.RouteTunnel || !slices.Equal(got.Via, via) {
		t.Errorf("an address: %+v", got)
	}
}
