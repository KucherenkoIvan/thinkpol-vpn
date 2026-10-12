package agent

import (
	"net/netip"
	"slices"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
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
		o.TunnelControl = dns.BindToInterface(r.dp.Interface)
	}
	return dns.New(o)
}

// systemConfig is how a device's OS should resolve now: through the
// resolver on its overlay addresses, short names in the space's zone.
func (r *runner) systemConfig() (dns.SystemConfig, bool) {
	if r.resolver == nil || r.section.Node.Kind != netmap.NodeDevice {
		return dns.SystemConfig{}, false
	}
	c := dns.SystemConfig{Interface: r.dp.Interface, Servers: []netip.Addr{r.section.Node.IPv4}}
	if r.engine.Status().IPv6 {
		c.Servers = append(c.Servers, r.section.Node.IPv6)
	}
	if netmap.CheckLabel(r.section.SpaceName) == nil {
		c.Search = []string{r.section.SpaceName + ".internal"}
	}
	return c, true
}

// pointSystem points a device's OS resolver at its resolver, or again
// when what it should point at changed.
func (r *runner) pointSystem() {
	want, ok := r.systemConfig()
	if !ok || r.system != nil && sameSystem(want, r.systemCfg) {
		return
	}
	r.restoreSystem()
	sys, err := r.dp.systemDNS(want)
	if err != nil {
		r.dp.Log.Error("DNS: the system doesn't resolve through the node: names may leave outside the tunnel", "err", err)
		return
	}
	r.system, r.systemCfg = sys, want
	r.dp.Log.Info("DNS: the system resolves through the node", "servers", want.Servers)
}

func (r *runner) restoreSystem() {
	if r.system == nil {
		return
	}
	if err := r.system.Restore(); err != nil {
		r.dp.Log.Warn("DNS: restoring the system's resolver configuration", "err", err)
	}
	r.system = nil
}

func sameSystem(a, b dns.SystemConfig) bool {
	return a.Interface == b.Interface && slices.Equal(a.Servers, b.Servers) && slices.Equal(a.Search, b.Search)
}
