package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
)

// The engine's ports (dataplane.InterfaceConfigurator, dataplane.RouteTable,
// dataplane.Resolver) over the host's adapters, which know nothing of the
// engine.

// overlayInterface is netcfg's configurator of the overlay as the
// engine's interface port.
type overlayInterface struct{ c netcfg.Configurator }

func (o overlayInterface) Apply(ctx context.Context, c dataplane.InterfaceConfig) error {
	ifc := netcfg.Interface{Name: c.Name, Addrs: c.Addrs, MTU: c.MTU, Up: c.Up}
	return o.c.Apply(ctx, netcfg.Config{Interfaces: []netcfg.Interface{ifc}})
}

func (o overlayInterface) Close() error { return o.c.Close() }

// routeTable is route-table enforcement as the engine's port, with what
// the engine doesn't know: the resolver's direct upstreams
// (routetable.Want.Upstreams: macOS's scoped routes, and the leak guard's
// exemption), set by SetDirectUpstreams.
type routeTable struct {
	rt RouteEnforcer

	// mu orders Enforce, SetDirectUpstreams and Close: every Enforce
	// carries the upstreams of its time.
	mu        sync.Mutex
	closed    bool
	want      *dataplane.RouteTableWant // last given; nil before the first
	upstreams []netip.AddrPort
}

// errRouteTableClosed is SetDirectUpstreams's error after Close.
var errRouteTableClosed = errors.New("route table closed")

func newRouteTable(rt RouteEnforcer) *routeTable { return &routeTable{rt: rt} }

func (t *routeTable) Enforce(ctx context.Context, w dataplane.RouteTableWant) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	// Kept for SetDirectUpstreams, whose callers run on other goroutines:
	// a copy of the engine's slices.
	w.Overlay, w.Bypass = slices.Clone(w.Overlay), slices.Clone(w.Bypass)
	t.want = &w // the route table keeps trying it
	return t.rt.Enforce(ctx, t.wantOf(w))
}

func (t *routeTable) wantOf(w dataplane.RouteTableWant) routetable.Want {
	return routetable.Want{
		TUN: w.TUN, Overlay: w.Overlay, Direct: w.Direct, Bypass: w.Bypass, IPv6: w.IPv6,
		Upstreams: t.upstreams,
	}
}

// SetDirectUpstreams says which direct DNS upstreams the node's resolver
// asks, so the route table keeps them reachable from the sockets bound to
// the physical interface. It re-enforces what is in place if they
// changed; before the first Enforce they are kept for it.
func (t *routeTable) SetDirectUpstreams(ctx context.Context, addrs []netip.AddrPort) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errRouteTableClosed
	}
	addrs = slices.Clone(addrs)
	slices.SortFunc(addrs, func(a, b netip.AddrPort) int { return a.Compare(b) })
	addrs = slices.Compact(addrs)
	if slices.Equal(addrs, t.upstreams) {
		return nil
	}
	t.upstreams = addrs
	if t.want == nil {
		return nil
	}
	if err := t.rt.Enforce(ctx, t.wantOf(*t.want)); err != nil {
		return fmt.Errorf("route table: %w", err)
	}
	return nil
}

func (t *routeTable) Status() dataplane.RouteTableStatus {
	st := t.rt.Status()
	return dataplane.RouteTableStatus{
		Enforced: st.Enforced, Error: routeTableError(st.Error), GuardEnforced: st.GuardEnforced, GuardError: routeTableError(st.GuardError),
		Routes: st.Routes, LastApply: st.LastApply,
		Reapplies: st.Reapplies, RulesAhead: st.RulesAhead, OverlayAhead: st.OverlayAhead,
	}
}

// routeTableError is the engine's code for the route table's error code p:
// none for none, and a failed apply for one the table doesn't know, so a
// problem is never lost.
func routeTableError(p routetable.ErrorCode) dataplane.RouteTableError {
	if p == "" {
		return ""
	}
	if e, ok := routeTableErrors[p]; ok {
		return e
	}
	return dataplane.RouteTableApplyFailed
}

// routeTableErrors are the engine's codes for the route table's problems.
var routeTableErrors = map[routetable.ErrorCode]dataplane.RouteTableError{
	routetable.ErrorApply:            dataplane.RouteTableApplyFailed,
	routetable.ErrorReapply:          dataplane.RouteTableReapplyFailed,
	routetable.ErrorUnsupported:      dataplane.RouteTableUnsupported,
	routetable.ErrorTUNDown:          dataplane.RouteTableTUNDown,
	routetable.ErrorGuard:            dataplane.RouteTableGuardFailed,
	routetable.ErrorGuardUnsupported: dataplane.RouteTableGuardUnsupported,
}

func (t *routeTable) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.closed = true
	return t.rt.Close()
}

// dnsResolver is the node's resolver as the engine's Resolver; listen, if
// valid, replaces where it listens and whom it answers (DataPlane's
// tuning.dnsListen).
type dnsResolver struct {
	s      *dns.Server
	listen netip.Addr
}

func (r dnsResolver) Update(c dataplane.ResolverConfig) {
	d := dnsConfig(c)
	if r.listen.IsValid() && len(d.Listen) > 0 {
		d.Listen = []netip.Addr{r.listen}
		d.Clients = []netip.Prefix{netip.PrefixFrom(r.listen, r.listen.BitLen())}
	}
	r.s.Update(d)
}

func dnsConfig(c dataplane.ResolverConfig) dns.Config {
	d := dns.Config{Listen: c.Listen, Clients: c.Clients, Zone: c.Zone, Names: c.Names, Overlay: c.Overlay}
	if route := c.Route; route != nil {
		d.Route = func(name string) dns.Route { return dnsRoute(route(name)) }
	}
	if route := c.RouteAddr; route != nil {
		d.RouteAddr = func(a netip.Addr) dns.Route { return dnsRoute(route(a)) }
	}
	return d
}

func dnsRoute(r dataplane.NameRoute) dns.Route {
	switch r.Kind {
	case dataplane.ResolveDirect:
		return dns.Route{Kind: dns.RouteDirect}
	case dataplane.ResolveTunnel:
		return dns.Route{Kind: dns.RouteTunnel, Via: r.Via}
	}
	return dns.Route{Kind: dns.RouteBlock}
}
