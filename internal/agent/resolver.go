package agent

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// newResolver makes the node's resolver for a start of its data plane:
// it asks the configured upstreams or, if there are none, the resolvers
// the OS uses now (read before the OS is pointed at the resolver; what the
// node itself wrote there is never taken for one). A device asks exits
// through the overlay TUN only.
func (r *runner) newResolver() *dns.Server {
	upstreams := r.dp.DNSUpstreams
	if len(upstreams) == 0 {
		own := []netip.Addr{r.section.Node.IPv4, r.section.Node.IPv6}
		host, err := r.dp.systemUpstreams(own)
		if err != nil {
			r.dp.Log.Warn("DNS: the system's resolvers are unknown; direct names won't resolve", "err", err)
		}
		for _, a := range host {
			upstreams = append(upstreams, netip.AddrPortFrom(a, dns.Port))
		}
	}
	if len(upstreams) == 0 {
		r.dp.Log.Warn("DNS: no upstream to ask; set one with -dns-upstream")
	}
	o := dns.Options{Upstreams: upstreams, Port: r.dp.dnsPort, Log: r.dp.Log}
	if r.section.Node.Kind == netmap.NodeDevice {
		o.TunnelControl = dns.BindToInterface(r.tun)
	}
	if r.dp.RouteTable {
		// The direct upstream's queries carry the links' mark (bound to
		// the physical interface on macOS), so they leave around the
		// tunnel whatever the route table holds.
		o.Control = routetable.SocketControl()
	}
	return dns.New(o)
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
// should not; nil when it doesn't, or when it isn't meant to.
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
	if r.resolver == nil || r.section.Node.Kind != netmap.NodeDevice {
		return dns.SystemConfig{}, false
	}
	c := dns.SystemConfig{Interface: r.tun, Servers: []netip.Addr{r.section.Node.IPv4}}
	if r.engine.Status().IPv6 {
		c.Servers = append(c.Servers, r.section.Node.IPv6)
	}
	if netmap.CheckLabel(r.section.SpaceName) == nil {
		c.Search = []string{r.section.SpaceName + ".internal"}
	}
	if len(r.dp.DNSUpstreams) == 0 {
		srv, own, log := r.resolver, []netip.Addr{r.section.Node.IPv4, r.section.Node.IPv6}, r.dp.Log
		c.Upstreams = func(host []netip.Addr) {
			var ups []netip.AddrPort
			for _, a := range host {
				if !slices.Contains(own, a) && !a.IsUnspecified() {
					ups = append(ups, netip.AddrPortFrom(a, dns.Port))
				}
			}
			srv.SetUpstreams(ups)
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
		sys, err = r.dp.systemDNS(want)
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
		r.dp.Log.Error("DNS: the system resolves through the node, but not only: names may leave outside the tunnel", "err", p)
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
