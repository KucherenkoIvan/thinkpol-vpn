package dataplane

import (
	"fmt"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// PathConfig is what the path layer takes from a node's section: the table
// for its Node, and the peers for its Binds.
type PathConfig struct {
	Table path.Table
	Peers []path.Peer
	// Skipped says what was left out of the section, and why.
	Skipped []SkipDetail
}

// PathConfigFrom converts a node's section for the path layer. The map's
// reader checks only that a section is well formed, so this skips what
// only the map builder rules out: endpoints of unknown transports, with no
// usable address, with shaping that doesn't decode, or that the transport
// refuses (shaping included); first and next hops that are not adjacent
// (neither dialed nor allowed to connect) or name the node itself; routes
// left with no next hop. A peer whose first hops are all skipped stays,
// with none: its packets are dropped until a map gives it a path.
func PathConfigFrom(s netmap.Section, reg *transport.Registry) PathConfig {
	b := pathConfigBuilder{self: s.Node.ID, adjacent: make(map[netmap.NodeID]bool)}
	for _, in := range s.Inbound {
		if s.Node.AcceptsInbound(in) {
			b.adjacent[in.Peer] = true
		}
	}
	b.links(s.Links, reg)
	b.routes(s.Routes)
	b.peers(s.Peers)
	return b.c
}

// pathConfigBuilder is PathConfigFrom's work: the node's own id, the nodes
// adjacent to it (dialed, or allowed to connect), and the config so far.
type pathConfigBuilder struct {
	c        PathConfig
	self     netmap.NodeID
	adjacent map[netmap.NodeID]bool
}

func (b *pathConfigBuilder) skip(node netmap.NodeID, what Item, reason Reason, err error) {
	b.c.Skipped = append(b.c.Skipped, skipOf(node, what, reason, err))
}

// links adds the links with a usable endpoint; their peers are adjacent.
func (b *pathConfigBuilder) links(links []netmap.Link, reg *transport.Registry) {
	for _, l := range links {
		if l.Peer.IsZero() || l.Peer == b.self {
			b.skip(l.Peer, ItemLink, ReasonNotANode, nil)
			continue
		}
		link := path.Link{Node: path.NodeID(l.Peer)}
		for i, e := range l.Endpoints {
			ep, reason, err := pathEndpoint(e, reg)
			if err != nil {
				b.skip(l.Peer, ItemEndpoint, reason, fmt.Errorf("endpoint %d: %w", i, err))
				continue
			}
			link.Endpoints = append(link.Endpoints, ep)
		}
		if len(link.Endpoints) == 0 {
			b.skip(l.Peer, ItemLink, ReasonNoEndpoint, nil)
			continue
		}
		b.adjacent[l.Peer] = true
		b.c.Table.Links = append(b.c.Table.Links, link)
	}
}

// hops are the ids of the adjacent nodes, other than the node itself, in
// ids: the hops of of's route or paths.
func (b *pathConfigBuilder) hops(of netmap.NodeID, ids []netmap.NodeID) []path.NodeID {
	var out []path.NodeID
	for _, h := range ids {
		if h == b.self || !b.adjacent[h] {
			b.skip(of, ItemHop, ReasonNotAdjacent, fmt.Errorf("hop %s", h))
			continue
		}
		out = append(out, path.NodeID(h))
	}
	return out
}

// routes adds the routes left with a next hop.
func (b *pathConfigBuilder) routes(routes []netmap.Route) {
	for _, r := range routes {
		if r.Destination.IsZero() || r.Destination == b.self {
			b.skip(r.Destination, ItemRoute, ReasonNotANode, nil)
			continue
		}
		next := b.hops(r.Destination, r.NextHops)
		if len(next) == 0 {
			b.skip(r.Destination, ItemRoute, ReasonNoNextHop, nil)
			continue
		}
		b.c.Table.Routes = append(b.c.Table.Routes, path.Route{Destination: path.NodeID(r.Destination), NextHops: next})
	}
}

// peers adds the peers, each with its usable first hops (perhaps none).
func (b *pathConfigBuilder) peers(peers []netmap.Peer) {
	for _, p := range peers {
		if p.ID.IsZero() || p.ID == b.self {
			b.skip(p.ID, ItemPeer, ReasonNotANode, nil)
			continue
		}
		first := make([]netmap.NodeID, 0, len(p.Paths))
		for _, pp := range p.Paths {
			first = append(first, pp.FirstHop)
		}
		peer := path.Peer{ID: path.NodeID(p.ID), FirstHops: b.hops(p.ID, first)}
		if len(peer.FirstHops) == 0 {
			b.skip(p.ID, ItemPeer, ReasonNoPath, nil)
		}
		b.c.Peers = append(b.c.Peers, peer)
	}
}

func pathEndpoint(e netmap.Endpoint, reg *transport.Registry) (path.Endpoint, Reason, error) {
	tr, ok := reg.Get(e.Transport)
	if !ok {
		return path.Endpoint{}, ReasonUnknownTransport, fmt.Errorf("unknown transport %q", e.Transport)
	}
	if !e.Address.IsValid() || e.Address.Port() == 0 || e.Address.Addr().IsUnspecified() {
		return path.Endpoint{}, ReasonUnusableAddress, fmt.Errorf("unusable address %q", e.Address)
	}
	shaping, err := transport.ParseShaping(e.Shaping)
	if err != nil {
		return path.Endpoint{}, ReasonBadShaping, fmt.Errorf("shaping: %w", err)
	}
	ep := path.Endpoint{
		Transport: e.Transport,
		Dialer:    tr.Dialer(),
		Address:   e.Address.String(),
		Config:    transport.DialConfig{Credential: e.Credential, Settings: e.Settings, Shaping: shaping},
	}
	if err := tr.CheckEndpoint(ep.Address, ep.Config); err != nil {
		return path.Endpoint{}, ReasonRefused, err
	}
	return ep, 0, nil
}
