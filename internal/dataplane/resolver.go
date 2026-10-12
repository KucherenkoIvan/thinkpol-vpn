package dataplane

import (
	"net/netip"
	"slices"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/dns"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

func (e *Engine) updateDNS() {
	if e.cfg.DNS != nil {
		e.cfg.DNS.Update(e.dnsConfig())
	}
}

// dnsConfig is what the node's resolver serves now (DESIGN.md "DNS is
// routing"):
//
//   - a device's, on its overlay addresses, for itself only: the names of
//     the space's zone it may know (its own, and its WireGuard peers' now,
//     so a peer the map took away is gone from DNS with it), and every
//     other name by the rules: direct to the domestic upstream, a chain's
//     to the resolver at its exit's overlay address, the rest blocked;
//   - an exit's (a server that allows egress), on its overlay addresses,
//     for the space's overlay: every name to its own upstream;
//   - any other server's: none.
func (e *Engine) dnsConfig() dns.Config {
	c := dns.Config{Overlay: slices.Clone(e.networks)}
	switch {
	case e.kind == netmap.NodeServer && e.egress:
		c.Listen, c.Clients = slices.Clone(e.local), slices.Clone(e.networks)
		return c
	case e.kind != netmap.NodeDevice:
		return c
	}
	// The node's own processes reach its own addresses from them; a
	// peer's address (whatever its WireGuard device allows it) is never
	// one of them.
	c.Listen = slices.Clone(e.local)
	for _, a := range e.local {
		c.Clients = append(c.Clients, netip.PrefixFrom(a, a.BitLen()))
	}

	peers := make(map[netmap.NodeID][]netip.Addr)
	for _, d := range e.devices {
		for _, p := range d.peers {
			peers[p.ID] = slices.Clone(p.Addresses)
		}
	}
	if netmap.CheckLabel(e.spaceName) == nil {
		c.Zone = e.spaceName + ".internal"
		c.Names = make(map[string][]netip.Addr)
		claims := make(map[string]int)
		add := func(name string, addrs []netip.Addr) {
			if netmap.CheckLabel(name) != nil || len(addrs) == 0 {
				return
			}
			claims[name]++
			c.Names[name] = addrs
		}
		add(e.ownName, slices.Clone(e.local))
		for id, addrs := range peers {
			add(e.peerNames[id], addrs)
		}
		// A name two nodes claim names neither (Build never makes one).
		for name, n := range claims {
			if n > 1 {
				delete(c.Names, name)
			}
		}
	}

	names := e.nameRules
	via := make(map[string][]netip.Addr, len(e.chainExit))
	for chain, exit := range e.chainExit {
		if addrs := peers[exit]; len(addrs) > 0 {
			via[chain] = addrs
		}
	}
	c.Route = func(name string) dns.Route {
		if names == nil {
			return dns.Route{Kind: dns.RouteBlock}
		}
		switch a := names.Lookup(name); a.Kind {
		case netmap.ActionDirect:
			return dns.Route{Kind: dns.RouteDirect}
		case netmap.ActionChain:
			if v, ok := via[a.Chain]; ok {
				return dns.Route{Kind: dns.RouteTunnel, Via: v}
			}
		}
		return dns.Route{Kind: dns.RouteBlock}
	}
	return c
}
