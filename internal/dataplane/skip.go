package dataplane

import (
	"fmt"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// Item is the kind of section entry a Skip is about.
type Item uint8

const (
	ItemLink     Item = iota + 1 // a link the node dials
	ItemEndpoint                 // one endpoint of such a link
	ItemInbound                  // a link the node accepts
	ItemRoute                    // a route the node relays by
	ItemHop                      // a first hop of a peer, or a next hop of a route
	ItemPeer                     // a WireGuard peer
)

func (i Item) String() string {
	switch i {
	case ItemLink:
		return "link"
	case ItemEndpoint:
		return "endpoint"
	case ItemInbound:
		return "inbound link"
	case ItemRoute:
		return "route"
	case ItemHop:
		return "hop"
	case ItemPeer:
		return "peer"
	}
	return fmt.Sprintf("Item(%d)", uint8(i))
}

// Reason is why an entry was skipped, from a fixed vocabulary: unlike the
// errors behind it, it never quotes the map, so it can go into status and
// telemetry.
type Reason uint8

const (
	ReasonNotANode         Reason = iota + 1 // no node id, or the node itself
	ReasonUnknownTransport                   // no such transport in the registry
	ReasonUnusableAddress                    // not an IP and port a node can dial
	ReasonBadShaping                         // shaping that doesn't decode, or this node doesn't support
	ReasonRefused                            // the transport refused the entry
	ReasonNoEndpoint                         // a link left without a usable endpoint
	ReasonMTUTooSmall                        // a link that leaves less than MinOverlayMTU for the overlay
	ReasonNotAdjacent                        // a hop that is neither dialed nor allowed to connect
	ReasonNoNextHop                          // a route left without a next hop
	ReasonNoPath                             // a peer left without a first hop (it stays, unreachable)
	ReasonZeroKey                            // a peer without a WireGuard key
	ReasonOwnKey                             // a peer with the node's own WireGuard key
	ReasonOwnAddress                         // a peer with one of the node's own overlay addresses
	ReasonOutsideOverlay                     // a peer address outside the space's overlay networks
	ReasonNoAddress                          // a peer without an address the overlay carries
	ReasonKeyClaimed                         // a WireGuard key two peers claim
	ReasonAddressClaimed                     // an overlay address two peers claim
)

func (r Reason) String() string {
	switch r {
	case ReasonNotANode:
		return "not a node"
	case ReasonUnknownTransport:
		return "unknown transport"
	case ReasonUnusableAddress:
		return "unusable address"
	case ReasonBadShaping:
		return "unusable shaping"
	case ReasonRefused:
		return "refused by the transport"
	case ReasonNoEndpoint:
		return "no usable endpoint"
	case ReasonMTUTooSmall:
		return "MTU too small"
	case ReasonNotAdjacent:
		return "not an adjacent node"
	case ReasonNoNextHop:
		return "no next hop"
	case ReasonNoPath:
		return "no usable path"
	case ReasonZeroKey:
		return "zero WireGuard key"
	case ReasonOwnKey:
		return "the node's own WireGuard key"
	case ReasonOwnAddress:
		return "the node's own address"
	case ReasonOutsideOverlay:
		return "address outside the overlay"
	case ReasonNoAddress:
		return "no overlay address carried"
	case ReasonKeyClaimed:
		return "WireGuard key claimed by another peer"
	case ReasonAddressClaimed:
		return "address claimed by another peer"
	}
	return fmt.Sprintf("Reason(%d)", uint8(r))
}

// Skip is an entry of a node's section left out, or cut down: the node it
// is about (the link's or inbound link's peer, the route's destination,
// the peer), what it was and why.
type Skip struct {
	Node   netmap.NodeID
	What   Item
	Reason Reason
}

func (s Skip) String() string { return fmt.Sprintf("%s %s: %s", s.What, s.Node, s.Reason) }

// SkipDetail is a Skip with the error behind it, which may quote the map
// (endpoint addresses, settings): for the node's local debug log only,
// never for status or telemetry.
type SkipDetail struct {
	Skip
	Err error
}

func (d SkipDetail) Error() string { return fmt.Sprintf("%s: %v", d.Skip, d.Err) }

func (d SkipDetail) Unwrap() error { return d.Err }

func skipOf(node netmap.NodeID, what Item, reason Reason, err error) SkipDetail {
	if err == nil {
		err = fmt.Errorf("%s", reason)
	}
	return SkipDetail{Skip: Skip{Node: node, What: what, Reason: reason}, Err: err}
}

// skips drops the details.
func skips(details []SkipDetail) []Skip {
	out := make([]Skip, 0, len(details))
	for _, d := range details {
		out = append(out, d.Skip)
	}
	return out
}
