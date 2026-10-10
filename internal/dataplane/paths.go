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
	Skipped []error
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
	skip := func(format string, args ...any) { c.Skipped = append(c.Skipped, fmt.Errorf(format, args...)) }

	adjacent := make(map[netmap.NodeID]bool)
	for _, in := range s.Inbound {
		adjacent[in.Peer] = true
	}
	for _, l := range s.Links {
		if l.Peer.IsZero() || l.Peer == self {
			skip("link to %s: not an adjacent node", l.Peer)
			continue
		}
		link := path.Link{Node: path.NodeID(l.Peer)}
		for i, e := range l.Endpoints {
			ep, err := pathEndpoint(e, reg)
			if err != nil {
				skip("link to %s, endpoint %d: %w", l.Peer, i, err)
				continue
			}
			link.Endpoints = append(link.Endpoints, ep)
		}
		if len(link.Endpoints) == 0 {
			skip("link to %s: no usable endpoint", l.Peer)
			continue
		}
		adjacent[l.Peer] = true
		c.Table.Links = append(c.Table.Links, link)
	}

	hops := func(what string, ids []netmap.NodeID) []path.NodeID {
		var out []path.NodeID
		for _, h := range ids {
			if h == self || !adjacent[h] {
				skip("%s: hop %s is not an adjacent node", what, h)
				continue
			}
			out = append(out, path.NodeID(h))
		}
		return out
	}
	for _, r := range s.Routes {
		what := fmt.Sprintf("route to %s", r.Destination)
		if r.Destination.IsZero() || r.Destination == self {
			skip("%s: not a destination to relay to", what)
			continue
		}
		next := hops(what, r.NextHops)
		if len(next) == 0 {
			skip("%s: no next hop", what)
			continue
		}
		c.Table.Routes = append(c.Table.Routes, path.Route{Destination: path.NodeID(r.Destination), NextHops: next})
	}
	for _, p := range s.Peers {
		what := fmt.Sprintf("peer %s", p.ID)
		if p.ID.IsZero() || p.ID == self {
			skip("%s: not a peer", what)
			continue
		}
		first := make([]netmap.NodeID, 0, len(p.Paths))
		for _, pp := range p.Paths {
			first = append(first, pp.FirstHop)
		}
		peer := path.Peer{ID: path.NodeID(p.ID), FirstHops: hops(what, first)}
		if len(peer.FirstHops) == 0 {
			skip("%s: no usable path", what)
		}
		c.Peers = append(c.Peers, peer)
	}
	return c
}

func pathEndpoint(e netmap.Endpoint, reg *transport.Registry) (path.Endpoint, error) {
	tr, ok := reg.Get(e.Transport)
	if !ok {
		return path.Endpoint{}, fmt.Errorf("unknown transport %q", e.Transport)
	}
	if !e.Address.IsValid() || e.Address.Port() == 0 || e.Address.Addr().IsUnspecified() {
		return path.Endpoint{}, fmt.Errorf("unusable address %q", e.Address)
	}
	shaping, err := transport.ParseShaping(e.Shaping)
	if err != nil {
		return path.Endpoint{}, fmt.Errorf("shaping: %w", err)
	}
	ep := path.Endpoint{
		Transport: e.Transport,
		Dialer:    tr.Dialer(),
		Address:   e.Address.String(),
		Config:    transport.DialConfig{Credential: e.Credential, Settings: e.Settings, Shaping: shaping},
	}
	if err := tr.CheckEndpoint(ep.Address, ep.Config); err != nil {
		return path.Endpoint{}, err
	}
	return ep, nil
}
