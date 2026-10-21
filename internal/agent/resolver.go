package agent

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/supervisor"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// newResolver makes the node's resolver for a start of its data plane:
// it asks the configured upstreams. A device with none asks the
// resolvers the OS uses now (read before the OS is pointed at the
// resolver; what the node itself wrote there is never taken for one); a
// worker never falls back to those (see DESIGN.md "Upstreams"). A device
// asks exits through the overlay TUN only.
func (r *runner) newResolver() *dns.Server {
	upstreams := r.dp.DNSUpstreams
	if len(upstreams) == 0 && !r.dp.inWorker {
		own := []netip.Addr{r.follow.section.Node.IPv4, r.follow.section.Node.IPv6}
		host, err := r.dp.Host.SystemUpstreams(own)
		r.upstreamsUnknown.Store(err != nil)
		if err != nil {
			r.dp.Log.Warn("DNS: the system's resolvers are unknown; direct names won't resolve until a read of them works", "err", err)
		}
		for _, a := range host {
			upstreams = append(upstreams, netip.AddrPortFrom(a, dns.Port))
		}
	}
	if len(upstreams) == 0 {
		if r.dp.inWorker {
			// workerUpstreams dropped every one: the egress refuses each.
			// An exit's are counted and logged there; a non-exit's
			// resolver reports nothing about them (MayEndAChain: only an
			// exit's resolver do devices ask), so it says this at debug.
			say := r.dp.Log.Warn
			if !r.follow.section.Node.MayEndAChain() {
				say = r.dp.Log.Debug
			}
			say("DNS: no upstream to ask: the egress refuses every configured one; tunnel-bound names won't resolve")
		} else if !r.upstreamsUnknown.Load() { // a failed read warned already
			r.dp.Log.Warn("DNS: no upstream to ask; set one with -dns-upstream")
		}
	}
	r.upstreams = slices.Clone(upstreams)
	o := dns.Options{Upstreams: upstreams, Port: r.dp.dnsPort, Log: r.dp.Log}
	if r.follow.section.Node.Kind == netmap.NodeDevice {
		o.TunnelControl = dns.BindToInterface(r.tun)
	}
	if r.dp.RouteTable {
		// The direct upstream's queries carry the links' mark, so they
		// leave around the tunnel whatever the route table holds. On
		// macOS they are bound to the physical interface instead, which
		// reaches only what a route on it reaches: the route table gives
		// each upstream a route scoped to it, and the leak guard exempts
		// them (routeTable.SetDirectUpstreams, the one source of both).
		o.Control = routetable.SocketControl()
	}
	return dns.New(o)
}

// upstreamsChanged gives the data plane a later config's upstream list:
// a resolver started later reads it (newResolver), a running one is
// switched to it at once.
func (r *runner) upstreamsChanged(ups []netip.AddrPort) {
	r.dp.DNSUpstreams = ups
	if r.resolver == nil {
		return
	}
	r.resolver.SetUpstreams(ups)
	r.upstreams = ups
	r.dp.Log.Info("DNS: the resolver's upstreams changed", "upstreams", len(ups))
}

// dnsGuard is a device's OS resolver configuration while it should
// resolve through the node, and why it may not: read by the status from
// any goroutine.
type dnsGuard struct {
	mu  sync.Mutex
	on  bool // the OS should resolve through the node now
	sys dns.System
	err error // pointing the OS failed
}

func (g *dnsGuard) set(on bool, sys dns.System, err error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.on, g.sys, g.err = on, sys, err
}

func (g *dnsGuard) system() dns.System {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sys
}

// problem says why the OS may resolve names outside the node while it
// should not (or that the direct upstreams may be stale,
// dns.ErrUpstreamsStale, which isn't unprotected); nil when neither, or
// when it isn't meant to.
func (g *dnsGuard) problem() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	switch {
	case !g.on:
		return nil
	case g.err != nil:
		return g.err
	case g.sys != nil:
		return g.sys.Problem()
	}
	return nil
}

// systemConfig is how a device's OS should resolve now: through the
// resolver on its overlay addresses, short names in the space's zone.
// Unless upstreams are configured, the resolver follows the OS's own
// resolvers when another program changes them.
func (r *runner) systemConfig() (dns.SystemConfig, bool) {
	if r.resolver == nil || r.follow.section.Node.Kind != netmap.NodeDevice {
		return dns.SystemConfig{}, false
	}
	c := dns.SystemConfig{Interface: r.tun, Servers: []netip.Addr{r.follow.section.Node.IPv4}, Log: r.dp.Log}
	if r.engine.Status().IPv6 {
		c.Servers = append(c.Servers, r.follow.section.Node.IPv6)
	}
	if netmap.CheckLabel(r.follow.section.SpaceName) == nil {
		c.Search = []string{r.follow.section.SpaceName + ".internal"}
	}
	if len(r.dp.DNSUpstreams) == 0 {
		srv, own, log := r.resolver, []netip.Addr{r.follow.section.Node.IPv4, r.follow.section.Node.IPv6}, r.dp.Log
		routes, unknown := r.routes, &r.upstreamsUnknown
		c.UpstreamsUnknown = unknown.Load()
		c.Upstreams = func(host []netip.Addr) {
			unknown.Store(false)
			var ups []netip.AddrPort
			for _, a := range host {
				if !slices.Contains(own, a) && !a.IsUnspecified() {
					ups = append(ups, netip.AddrPortFrom(a, dns.Port))
				}
			}
			srv.SetUpstreams(ups)
			if routes != nil {
				if err := routes.SetDirectUpstreams(context.Background(), ups); err != nil {
					log.Warn("DNS: keeping the direct upstreams reachable failed", "err", path.RedactError(err))
				}
			}
			log.Info("DNS: the system's own resolvers changed", "upstreams", len(ups))
		}
	}
	return c, true
}

// pointSystem points a device's OS resolver at its resolver, or updates
// it over the current configuration when what it should point at
// changed. A failure is retried on the retry timer, and reported
// (Status.DNSUnprotected) meanwhile.
func (r *runner) pointSystem() {
	want, ok := r.systemConfig()
	if !ok {
		return
	}
	sys := r.guard.system()
	if sys != nil && sameSystem(want, r.systemCfg) {
		return
	}
	var err error
	if sys != nil {
		err = sys.Update(want)
	} else {
		sys, err = r.dp.Host.SetSystemDNS(want)
	}
	if err != nil {
		r.guard.set(true, sys, fmt.Errorf("%w: %v", dns.ErrUnprotected, err))
		r.dnsRetryAt = time.Now().Add(r.dp.retryAfter)
		r.dp.Log.Error("DNS: the system doesn't resolve through the node: names may leave outside the tunnel; retrying",
			"in", r.dp.retryAfter, "err", err)
		return
	}
	r.guard.set(true, sys, nil)
	r.systemCfg, r.dnsRetryAt = want, time.Time{}
	if p := sys.Problem(); p != nil {
		if dns.Unprotected(p) {
			r.dp.Log.Error("DNS: the system resolves through the node, but not only: names may leave outside the tunnel", "err", p)
		} else {
			// The OS configuration warned when the read failed: one
			// warning an episode.
			r.dp.Log.Info("DNS: the system resolves through the node; the direct upstreams may be stale", "err", p)
		}
		return
	}
	r.dp.Log.Info("DNS: the system resolves through the node", "servers", want.Servers)
}

func (r *runner) restoreSystem() {
	sys := r.guard.system()
	r.guard.set(false, nil, nil)
	r.systemCfg, r.dnsRetryAt = dns.SystemConfig{}, time.Time{}
	if sys == nil {
		return
	}
	if err := sys.Restore(); err != nil {
		r.dp.Log.Warn("DNS: restoring the system's resolver configuration", "err", err)
	}
}

func sameSystem(a, b dns.SystemConfig) bool {
	return a.Interface == b.Interface && slices.Equal(a.Servers, b.Servers) && slices.Equal(a.Search, b.Search)
}

// defaultWorkerUpstreams are the upstreams an exit's resolver asks when
// -dns-upstream is unset: Quad9 then Cloudflare over IPv4, then both
// over IPv6 (DESIGN.md "Upstreams"). workerUpstreams puts the family the
// uplink carries first when it carries exactly one, so a single-family
// exit doesn't wait out a dead family's timeout.
var defaultWorkerUpstreams = []netip.AddrPort{
	netip.AddrPortFrom(netip.MustParseAddr("9.9.9.9"), dns.Port),
	netip.AddrPortFrom(netip.MustParseAddr("1.1.1.1"), dns.Port),
	netip.AddrPortFrom(netip.MustParseAddr("2620:fe::fe"), dns.Port),
	netip.AddrPortFrom(netip.MustParseAddr("2606:4700:4700::1111"), dns.Port),
}

// orderForUplink returns the defaults stable-sorted so the family the
// uplink carries comes first when it carries exactly one, the static
// order kept within a family; with both or neither carried, the static
// order stands. It always returns a copy.
func orderForUplink(ups []netip.AddrPort, e supervisor.EgressInfo) []netip.AddrPort {
	out := slices.Clone(ups)
	if e.IPv4 == e.IPv6 {
		return out
	}
	slices.SortStableFunc(out, func(a, b netip.AddrPort) int {
		afirst, bfirst := a.Addr().Is4() == e.IPv4, b.Addr().Is4() == e.IPv4
		switch {
		case afirst && !bfirst:
			return -1
		case !afirst && bfirst:
			return 1
		}
		return 0
	})
	return out
}

// workerUpstreams are the upstreams a worker's resolver asks: the
// configured ones, else the default public resolvers (DESIGN.md
// "Upstreams"), ordered for the uplink's families. One the worker's
// egress refuses is not configured: only an exit's (a server allowing
// egress, MayEndAChain) are counted and logged, since no device asks
// another server's resolver. e is the uplink snapshot the caller's apply
// goes on, so the order and the "map applied" line agree.
func (s *serverSpaces) workerUpstreams(e supervisor.EgressInfo) []netip.AddrPort {
	if !s.dns {
		return nil
	}
	ups := s.dnsUpstreams
	if len(ups) == 0 {
		ups = orderForUplink(defaultWorkerUpstreams, e)
	}
	var out, refused []netip.AddrPort
	for _, a := range ups {
		if supervisor.EgressRefused(a.Addr(), s.egressAllowed) {
			refused = append(refused, a)
			continue
		}
		out = append(out, a)
	}
	if !s.follow.section.Node.MayEndAChain() {
		// Nothing remembered as logged, so a map that makes the node an
		// exit reports from scratch.
		s.refusedLogged = nil
		s.report.set(func(p *report) { p.dnsUpstreamsRefused = 0 })
		return out
	}
	if !slices.Equal(refused, s.refusedLogged) {
		for _, a := range refused {
			hint := "-dns-upstream or -egress-allowed"
			if supervisor.EgressNotWorthAllowing(a.Addr()) {
				hint = "-dns-upstream"
			}
			s.log.Warn("DNS: the worker's egress refuses the upstream; not configured for the resolver",
				"upstream", a, "hint", hint)
		}
		s.refusedLogged = refused
	}
	s.report.set(func(p *report) { p.dnsUpstreamsRefused = len(refused) })
	return out
}
