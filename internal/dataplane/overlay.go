package dataplane

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/router"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/wg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

const (
	// DefaultLinkMTU is the MTU assumed for the network under every link.
	DefaultLinkMTU = 1500
	// MinOverlayMTU is the smallest overlay MTU a node runs with: every
	// IPv4 host must take 576-byte packets.
	MinOverlayMTU = 576
	// MinIPv6MTU is IPv6's minimum link MTU; below it the overlay carries
	// IPv4 only.
	MinIPv6MTU = 1280
	// linkHeaders is what a link's own packets carry under the transport:
	// an IPv6 header (the larger family, whatever the endpoint's) and UDP.
	linkHeaders = 40 + 8
)

// ErrMTUTooSmall: a node's links leave less than MinOverlayMTU for the
// overlay's packets.
var ErrMTUTooSmall = errors.New("dataplane: overlay MTU below the minimum")

// OverlayMTU is the TUN MTU a node's links allow: the smallest WireGuard
// message budget (path.MessageBudget) over every endpoint it dials and every
// link it accepts, each with its own transport and shaping, less WireGuard's
// overhead, on a network of linkMTU under each link (0 means
// DefaultLinkMTU). Links are budgeted as IPv6 whatever their endpoint, so
// the space's nodes agree as long as their links do: 1328 for unshaped udp
// over 1500. A node with no usable link gets the budget of the registry's
// transports, unshaped.
func OverlayMTU(pc PathConfig, in InboundConfig, reg *transport.Registry, linkMTU int) int {
	if linkMTU <= 0 {
		linkMTU = DefaultLinkMTU
	}
	unit := linkMTU - linkHeaders
	budget := -1
	use := func(name string, s transport.Shaping) {
		if t, ok := reg.Get(name); ok {
			if b := path.MessageBudget(t, s, unit); budget < 0 || b < budget {
				budget = b
			}
		}
	}
	for _, l := range pc.Table.Links {
		for _, e := range l.Endpoints {
			use(e.Transport, e.Config.Shaping)
		}
	}
	for name, links := range in.Links {
		for _, pl := range links {
			use(name, pl.Shaping)
		}
	}
	if budget < 0 {
		for _, name := range reg.Names() {
			use(name, transport.Shaping{})
		}
	}
	return min(budget-wg.Overhead, router.MaxPacket)
}

// OverlayConfig is what the overlay takes from a node's section: the TUN's
// addresses and MTU, the networks the router decides by peers alone, and
// the WireGuard peers.
type OverlayConfig struct {
	// Addrs are the node's own overlay addresses, with the length of their
	// network, for the TUN.
	Addrs []netip.Prefix
	// Networks are the space's overlay networks the overlay carries.
	Networks []netip.Prefix
	MTU      int
	// IPv6Off says why the overlay carries no IPv6, when it doesn't.
	IPv6Off error
	Peers   []OverlayPeer
	// Skipped says what was left out of the section, and why.
	Skipped []error
}

// OverlayPeer is a WireGuard peer on the overlay.
type OverlayPeer struct {
	ID  netmap.NodeID
	Key netmap.WireGuardKey
	// Addresses are the peer's overlay addresses, of the families the
	// overlay carries: its WireGuard allowed IPs.
	Addresses []netip.Addr
}

// OverlayConfigFrom converts a node's section for the overlay, with own
// as the node's WireGuard public key and mtu its overlay MTU (OverlayMTU).
// It fails on an MTU below MinOverlayMTU and without a usable IPv4 overlay
// address. IPv6 is off below MinIPv6MTU or without a usable IPv6 address,
// and IPv6Off says so.
//
// The map's reader leaves a section's peers unchecked against each other,
// and WireGuard silently moves an allowed IP shared by two peers to the
// last one, so peers that can't be configured safely are skipped: those
// with the node's own or a zero key, an address outside the overlay
// networks or of the node itself, and every peer of a key or an address
// that two peers claim (either might be the wrong one).
func OverlayConfigFrom(s netmap.Section, own netmap.WireGuardKey, mtu int) (OverlayConfig, error) {
	if mtu < MinOverlayMTU {
		return OverlayConfig{}, fmt.Errorf("%w: %d, less than %d", ErrMTUTooSmall, mtu, MinOverlayMTU)
	}
	n := s.Node
	c := OverlayConfig{MTU: mtu}
	if !usable(n.IPv4, n.IPv4Network, true) {
		return OverlayConfig{}, fmt.Errorf("dataplane: no usable overlay IPv4 address (%s in %s)", n.IPv4, n.IPv4Network)
	}
	c.Addrs = append(c.Addrs, netip.PrefixFrom(n.IPv4, n.IPv4Network.Bits()))
	c.Networks = append(c.Networks, n.IPv4Network.Masked())
	switch {
	case mtu < MinIPv6MTU:
		c.IPv6Off = fmt.Errorf("overlay MTU %d is below IPv6's minimum of %d", mtu, MinIPv6MTU)
	case !usable(n.IPv6, n.IPv6Network, false):
		c.IPv6Off = fmt.Errorf("no usable overlay IPv6 address (%s in %s)", n.IPv6, n.IPv6Network)
	default:
		c.Addrs = append(c.Addrs, netip.PrefixFrom(n.IPv6, n.IPv6Network.Bits()))
		c.Networks = append(c.Networks, n.IPv6Network.Masked())
	}
	inOverlay := func(a netip.Addr) bool {
		for _, p := range c.Networks {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}

	skip := func(p netmap.Peer, format string, args ...any) {
		c.Skipped = append(c.Skipped, fmt.Errorf("peer %s: %s", p.ID, fmt.Sprintf(format, args...)))
	}
	var candidates []OverlayPeer
	keys := make(map[netmap.WireGuardKey]int)
	claims := make(map[netip.Addr]int)
peers:
	for _, p := range s.Peers {
		switch {
		case p.ID.IsZero() || p.ID == n.ID:
			skip(p, "not a peer")
			continue
		case p.WireGuardKey.IsZero():
			skip(p, "zero WireGuard key")
			continue
		case p.WireGuardKey == own:
			skip(p, "the node's own WireGuard key")
			continue
		}
		op := OverlayPeer{ID: p.ID, Key: p.WireGuardKey}
		for _, a := range p.Addresses {
			switch {
			case a.IsValid() && a.Is6() && !a.Is4In6() && c.IPv6Off != nil:
				continue // the overlay doesn't carry it
			case !a.IsValid() || a.Zone() != "" || !inOverlay(a):
				skip(p, "address %s outside the overlay", a)
				continue peers
			case a == n.IPv4 || a == n.IPv6:
				skip(p, "the node's own address %s", a)
				continue peers
			}
			op.Addresses = append(op.Addresses, a)
		}
		if len(op.Addresses) == 0 {
			skip(p, "no overlay address the overlay carries")
			continue
		}
		keys[op.Key]++
		for _, a := range op.Addresses {
			claims[a]++
		}
		candidates = append(candidates, op)
	}
	for _, op := range candidates {
		if keys[op.Key] > 1 {
			c.Skipped = append(c.Skipped, fmt.Errorf("peer %s: WireGuard key %s claimed by another peer", op.ID, op.Key))
			continue
		}
		shared := false
		for _, a := range op.Addresses {
			if claims[a] > 1 {
				c.Skipped = append(c.Skipped, fmt.Errorf("peer %s: address %s claimed by another peer", op.ID, a))
				shared = true
				break
			}
		}
		if !shared {
			c.Peers = append(c.Peers, op)
		}
	}
	return c, nil
}

// usable reports whether a is an address of the right family inside
// network.
func usable(a netip.Addr, network netip.Prefix, v4 bool) bool {
	return a.IsValid() && network.IsValid() && a.Is4() == v4 && network.Addr().Is4() == v4 &&
		a.Zone() == "" && network.Contains(a)
}
