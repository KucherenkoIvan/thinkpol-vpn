package dataplane

import (
	"net/netip"
	"slices"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Resolver is the node's resolver: Update replaces what it serves.
type Resolver interface {
	Update(c ResolverConfig)
}

// ResolverConfig is what the node's resolver serves.
type ResolverConfig struct {
	// Listen are the addresses to serve on: the node's overlay addresses.
	// None: the resolver doesn't listen.
	Listen []netip.Addr
	// Clients are the sources that may ask; anyone else is refused.
	Clients []netip.Prefix
	// Zone is the space's zone, `<space>.internal`, lowercase without the
	// trailing dot; empty: no overlay names.
	Zone string
	// Names are the overlay names in Zone, by label, and their addresses.
	Names map[string][]netip.Addr
	// Overlay are the space's overlay networks: their reverse names are
	// answered from Names, never forwarded.
	Overlay []netip.Prefix
	// Route decides where a name outside `.internal` is resolved (the name
	// lowercase, without the trailing dot). Nil: every name direct.
	Route func(name string) NameRoute
	// RouteAddr decides where the reverse name (PTR) of an address outside
	// the overlay is resolved: where the address's packets go. Nil: direct.
	RouteAddr func(netip.Addr) NameRoute
}

// NameRouteKind is where a name's query goes.
type NameRouteKind uint8

const (
	// ResolveDirect asks the domestic upstream, around the tunnel.
	ResolveDirect NameRouteKind = iota + 1
	// ResolveTunnel asks the resolver at an exit, through the tunnel.
	ResolveTunnel
	// ResolveBlock asks no one: the query fails.
	ResolveBlock
)

// NameRoute is where one name's query goes.
type NameRoute struct {
	Kind NameRouteKind
	// Via are the exit's overlay addresses, for ResolveTunnel: its
	// resolver is there.
	Via []netip.Addr
}

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
func (e *Engine) dnsConfig() ResolverConfig {
	c := ResolverConfig{Overlay: slices.Clone(e.networks)}
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
	for _, d := range e.devices.byName {
		for _, p := range d.peers {
			peers[p.ID] = slices.Clone(p.Addresses)
		}
	}
	if netmap.CheckLabel(e.spaceName) == nil {
		c.Zone, c.Names = e.spaceName+".internal", e.zoneNames(peers)
	}
	c.Route, c.RouteAddr = e.nameRoutes(peers)
	return c
}

// zoneNames are the names of the space's zone a device may know: its own,
// and its WireGuard peers' (peers, by id), each a single label; a name two
// nodes claim names neither (Build never makes one).
func (e *Engine) zoneNames(peers map[netmap.NodeID][]netip.Addr) map[string][]netip.Addr {
	names := make(map[string][]netip.Addr)
	claims := make(map[string]int)
	add := func(name string, addrs []netip.Addr) {
		if netmap.CheckLabel(name) != nil || len(addrs) == 0 {
			return
		}
		claims[name]++
		names[name] = addrs
	}
	add(e.ownName, slices.Clone(e.local))
	for id, addrs := range peers {
		add(e.peerNames[id], addrs)
	}
	for name, n := range claims {
		if n > 1 {
			delete(names, name)
		}
	}
	return names
}

// nameRoutes route a name by the rules compiled for names, and a reverse
// name where its address's packets go: direct, through a chain to the
// resolver at its exit's overlay address (peers, by id), or blocked.
func (e *Engine) nameRoutes(peers map[netmap.NodeID][]netip.Addr) (byName func(string) NameRoute, byAddr func(netip.Addr) NameRoute) {
	names := e.nameRules
	via := make(map[string][]netip.Addr, len(e.chainExit))
	for chain, exit := range e.chainExit {
		if addrs := peers[exit]; len(addrs) > 0 {
			via[chain] = addrs
		}
	}
	route := func(a netmap.Action) NameRoute {
		switch a.Kind {
		case netmap.ActionDirect:
			return NameRoute{Kind: ResolveDirect}
		case netmap.ActionChain:
			if v, ok := via[a.Chain]; ok {
				return NameRoute{Kind: ResolveTunnel, Via: v}
			}
		}
		return NameRoute{Kind: ResolveBlock}
	}
	byName = func(name string) NameRoute {
		if names == nil {
			return NameRoute{Kind: ResolveBlock}
		}
		return route(names.Lookup(name))
	}
	table := e.ruleTable
	byAddr = func(a netip.Addr) NameRoute {
		if table == nil {
			return NameRoute{Kind: ResolveBlock}
		}
		action, ok := table.Lookup(a)
		if !ok {
			return NameRoute{Kind: ResolveBlock}
		}
		return route(action)
	}
	return byName, byAddr
}
