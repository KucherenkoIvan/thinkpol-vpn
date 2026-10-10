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
	var c PathConfig
	self := s.Node.ID
	skip := func(node netmap.NodeID, what Item, reason Reason, err error) {
		c.Skipped = append(c.Skipped, skipOf(node, what, reason, err))
	}

	adjacent := make(map[netmap.NodeID]bool)
	for _, in := range s.Inbound {
		adjacent[in.Peer] = true
	}
	for _, l := range s.Links {
		if l.Peer.IsZero() || l.Peer == self {
			skip(l.Peer, ItemLink, ReasonNotANode, nil)
			continue
		}
		link := path.Link{Node: path.NodeID(l.Peer)}
		for i, e := range l.Endpoints {
			ep, reason, err := pathEndpoint(e, reg)
			if err != nil {
				skip(l.Peer, ItemEndpoint, reason, fmt.Errorf("endpoint %d: %w", i, err))
				continue
			}
			link.Endpoints = append(link.Endpoints, ep)
		}
		if len(link.Endpoints) == 0 {
			skip(l.Peer, ItemLink, ReasonNoEndpoint, nil)
			continue
		}
		adjacent[l.Peer] = true
		c.Table.Links = append(c.Table.Links, link)
	}

	hops := func(of netmap.NodeID, ids []netmap.NodeID) []path.NodeID {
		var out []path.NodeID
		for _, h := range ids {
			if h == self || !adjacent[h] {
				skip(of, ItemHop, ReasonNotAdjacent, fmt.Errorf("hop %s", h))
				continue
			}
			out = append(out, path.NodeID(h))
		}
		return out
	}
	for _, r := range s.Routes {
		if r.Destination.IsZero() || r.Destination == self {
			skip(r.Destination, ItemRoute, ReasonNotANode, nil)
			continue
		}
		next := hops(r.Destination, r.NextHops)
		if len(next) == 0 {
			skip(r.Destination, ItemRoute, ReasonNoNextHop, nil)
			continue
		}
		c.Table.Routes = append(c.Table.Routes, path.Route{Destination: path.NodeID(r.Destination), NextHops: next})
	}
	for _, p := range s.Peers {
		if p.ID.IsZero() || p.ID == self {
			skip(p.ID, ItemPeer, ReasonNotANode, nil)
			continue
		}
		first := make([]netmap.NodeID, 0, len(p.Paths))
		for _, pp := range p.Paths {
			first = append(first, pp.FirstHop)
		}
		peer := path.Peer{ID: path.NodeID(p.ID), FirstHops: hops(p.ID, first)}
		if len(peer.FirstHops) == 0 {
			skip(p.ID, ItemPeer, ReasonNoPath, nil)
		}
		c.Peers = append(c.Peers, peer)
	}
	return c
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
