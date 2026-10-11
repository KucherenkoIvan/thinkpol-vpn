package dataplane

import (
	"fmt"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// InboundConfig is what a node's listeners take from its section: the
// links each transport's listeners accept.
type InboundConfig struct {
	// Links are keyed by transport name.
	Links map[string][]transport.PeerLink
	// Skipped says what was left out of the section, and why.
	Skipped []SkipDetail
}

// InboundFrom converts a node's inbound links for its listeners, stamping
// every link with space: the space whose map it came from, never anything
// the map says. It skips links from no node or from the node itself, of
// unknown transports, with shaping that doesn't decode, and those the
// transport refuses.
func InboundFrom(s netmap.Section, reg *transport.Registry, space transport.SpaceID) InboundConfig {
	c := InboundConfig{Links: make(map[string][]transport.PeerLink)}
	for _, in := range s.Inbound {
		pl, reason, err := peerLink(in, reg, space, s.Node.ID)
		if err != nil {
			c.Skipped = append(c.Skipped, skipOf(in.Peer, ItemInbound, reason, fmt.Errorf("over %q: %w", in.Transport, err)))
			continue
		}
		c.Links[in.Transport] = append(c.Links[in.Transport], pl)
	}
	return c
}

func peerLink(in netmap.InboundLink, reg *transport.Registry, space transport.SpaceID, self netmap.NodeID) (transport.PeerLink, Reason, error) {
	if in.Peer.IsZero() || in.Peer == self {
		return transport.PeerLink{}, ReasonNotANode, fmt.Errorf("not an adjacent node")
	}
	tr, ok := reg.Get(in.Transport)
	if !ok {
		return transport.PeerLink{}, ReasonUnknownTransport, fmt.Errorf("unknown transport")
	}
	shaping, err := transport.ParseShaping(in.Shaping)
	if err != nil {
		return transport.PeerLink{}, ReasonBadShaping, fmt.Errorf("shaping: %w", err)
	}
	pl := transport.PeerLink{
		Peer:     transport.Identity{Space: space, Node: transport.NodeID(in.Peer)},
		Verifier: in.Credential,
		Settings: in.Settings,
		Shaping:  shaping,
	}
	if err := tr.CheckInbound(pl); err != nil {
		return transport.PeerLink{}, ReasonRefused, err
	}
	return pl, 0, nil
}

// AcceptedInbound is the one source of every inbound table: what a node's
// listeners accept, per transport, for space. The engine serves it, and a
// server's supervisor authenticates its shared listeners against each
// space's AcceptedInbound, so the two can't disagree. It is InboundFrom
// less the links too small for the overlay over linkMTU (OverlayMTU's
// rule; 0 means DefaultLinkMTU). Node settings that restrict who may
// connect (TP-013's ingress) belong here too.
func AcceptedInbound(s netmap.Section, reg *transport.Registry, space transport.SpaceID, linkMTU int) InboundConfig {
	in := InboundFrom(s, reg, space)
	OverlayMTU(&PathConfig{}, &in, reg, linkMTU)
	return in
}
