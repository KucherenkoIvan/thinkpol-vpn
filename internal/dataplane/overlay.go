package dataplane

import (
	"errors"
	"fmt"
	"net/netip"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/wg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

const (
	// DefaultLinkMTU is the MTU assumed for the network under every link.
	DefaultLinkMTU = 1500
	// MinOverlayMTU is the smallest overlay MTU a node runs with: every
	// IPv4 host must take 576-byte packets.
	MinOverlayMTU = path.MinOverlayMTU
	// MinIPv6MTU is IPv6's minimum link MTU; below it the overlay carries
	// IPv4 only.
	MinIPv6MTU = 1280
	// linkHeaders is what a link's own packets carry under the transport:
	// an IPv6 header (the larger family, whatever the endpoint's) and UDP.
	linkHeaders = 40 + 8
)

var (
	// ErrMTUTooSmall: not even the transports' unshaped budget leaves
	// MinOverlayMTU for the overlay.
	ErrMTUTooSmall = errors.New("dataplane: overlay MTU below the minimum")
	// ErrIPv6MTU and ErrNoIPv6Address say why an overlay carries no IPv6.
	ErrIPv6MTU       = errors.New("overlay MTU below IPv6's minimum of 1280")
	ErrNoIPv6Address = errors.New("no usable overlay IPv6 address")
)

// IPv6Off says why an overlay carries no IPv6 (Status.IPv6Off): a code.
type IPv6Off string

const (
	IPv6OffMTU       IPv6Off = "mtu_below_1280"  // ErrIPv6MTU
	IPv6OffNoAddress IPv6Off = "no_ipv6_address" // ErrNoIPv6Address
)

var ipv6OffCodes = map[error]IPv6Off{ErrIPv6MTU: IPv6OffMTU, ErrNoIPv6Address: IPv6OffNoAddress}

// OverlayMTU is the TUN MTU a node's links allow: the smallest WireGuard
// message budget (path.MessageBudget) over every endpoint it dials and every
// link it accepts, each with its own transport and shaping, less WireGuard's
// overhead, on a network of linkMTU under each link (0 means
// DefaultLinkMTU). Links are budgeted as IPv6 whatever the family of their
// endpoint, so nodes agree as long as their links do: 1328 for unshaped udp
// over 1500. This is the node's own floor: the space-wide overlay MTU is
// the map builder's (TP-030), and a relay drops and counts what is too long
// for its next link (path.Counters.TooLarge).
//
// A link that leaves less than MinOverlayMTU is dropped from pc and in
// (skipped as ReasonMTUTooSmall) rather than holding the node back: the
// rest of the section still applies, revocations included. With no link
// left, the registry's transports, unshaped, give the budget.
func OverlayMTU(pc *PathConfig, in *InboundConfig, reg *transport.Registry, linkMTU int) int {
	if linkMTU <= 0 {
		linkMTU = DefaultLinkMTU
	}
	unit := linkMTU - linkHeaders
	overlay := func(name string, s transport.Shaping) (int, bool) {
		t, ok := reg.Get(name)
		if !ok {
			return 0, false
		}
		return path.MessageBudget(t, s, unit) - wg.Overhead, true
	}
	mtu := -1
	use := func(m int) {
		if mtu < 0 || m < mtu {
			mtu = m
		}
	}

	links := pc.Table.Links[:0]
	for _, l := range pc.Table.Links {
		eps := l.Endpoints[:0]
		for _, e := range l.Endpoints {
			m, ok := overlay(e.Transport, e.Config.Shaping)
			if !ok || m < MinOverlayMTU {
				pc.Skipped = append(pc.Skipped, skipOf(netmap.NodeID(l.Node), ItemEndpoint, ReasonMTUTooSmall,
					fmt.Errorf("%s endpoint leaves %d bytes for the overlay", e.Transport, m)))
				continue
			}
			use(m)
			eps = append(eps, e)
		}
		if len(eps) == 0 {
			pc.Skipped = append(pc.Skipped, skipOf(netmap.NodeID(l.Node), ItemLink, ReasonMTUTooSmall, nil))
			continue
		}
		l.Endpoints = eps
		links = append(links, l)
	}
	pc.Table.Links = links

	for name, pls := range in.Links {
		kept := pls[:0]
		for _, pl := range pls {
			m, ok := overlay(name, pl.Shaping)
			if !ok || m < MinOverlayMTU {
				in.Skipped = append(in.Skipped, skipOf(netmap.NodeID(pl.Peer.Node), ItemInbound, ReasonMTUTooSmall,
					fmt.Errorf("%s link leaves %d bytes for the overlay", name, m)))
				continue
			}
			use(m)
			kept = append(kept, pl)
		}
		in.Links[name] = kept
	}

	if mtu < 0 {
		for _, name := range reg.Names() {
			m, _ := overlay(name, transport.Shaping{})
			use(m)
		}
	}
	return mtu
}

// OverlayConfig is what the overlay takes from a node's section.
type OverlayConfig struct {
	// Addrs are the node's own overlay addresses the overlay carries, with
	// the length of their network, for the TUN.
	Addrs []netip.Prefix
	// Local are the same addresses: the only destinations WireGuard may
	// deliver to.
	Local []netip.Addr
	// Networks are the space's overlay networks, carried or not: the
	// router decides every destination inside them by peers alone.
	Networks []netip.Prefix
	MTU      int
	// IPv6Off says why the overlay carries no IPv6, when it doesn't
	// (ErrIPv6MTU, ErrNoIPv6Address).
	IPv6Off error
	Peers   []OverlayPeer
	// Skipped says what was left out of the section, and why.
	Skipped []SkipDetail
}

// OverlayPeer is a WireGuard peer on the overlay.
type OverlayPeer struct {
	ID  netmap.NodeID
	Key netmap.WireGuardKey
	// Addresses are the peer's overlay addresses, of the families the
	// overlay carries.
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
		return OverlayConfig{}, errors.New("dataplane: no usable overlay IPv4 address")
	}
	c.Addrs = append(c.Addrs, netip.PrefixFrom(n.IPv4, n.IPv4Network.Bits()))
	c.Local = append(c.Local, n.IPv4)
	c.Networks = append(c.Networks, n.IPv4Network.Masked())
	if v6 := n.IPv6Network; v6.IsValid() && v6.Addr().Is6() && !v6.Addr().Is4In6() && v6.Addr().Zone() == "" {
		c.Networks = append(c.Networks, v6.Masked())
	}
	switch {
	case mtu < MinIPv6MTU:
		c.IPv6Off = ErrIPv6MTU
	case !usable(n.IPv6, n.IPv6Network, false):
		c.IPv6Off = ErrNoIPv6Address
	default:
		c.Addrs = append(c.Addrs, netip.PrefixFrom(n.IPv6, n.IPv6Network.Bits()))
		c.Local = append(c.Local, n.IPv6)
	}
	inOverlay := func(a netip.Addr) bool {
		for _, p := range c.Networks {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}

	skip := func(p netmap.NodeID, reason Reason, err error) {
		c.Skipped = append(c.Skipped, skipOf(p, ItemPeer, reason, err))
	}
	var candidates []OverlayPeer
	keys := make(map[netmap.WireGuardKey]int)
	claims := make(map[netip.Addr]int)
peers:
	for _, p := range s.Peers {
		switch {
		case p.ID.IsZero() || p.ID == n.ID:
			skip(p.ID, ReasonNotANode, nil)
			continue
		case p.WireGuardKey.IsZero():
			skip(p.ID, ReasonZeroKey, nil)
			continue
		case p.WireGuardKey == own:
			skip(p.ID, ReasonOwnKey, nil)
			continue
		}
		op := OverlayPeer{ID: p.ID, Key: p.WireGuardKey}
		for _, a := range p.Addresses {
			switch {
			case a.IsValid() && a.Is6() && !a.Is4In6() && c.IPv6Off != nil:
				continue // the overlay doesn't carry it
			case !a.IsValid() || a.Zone() != "" || !inOverlay(a):
				skip(p.ID, ReasonOutsideOverlay, fmt.Errorf("address %s", a))
				continue peers
			case a == n.IPv4 || a == n.IPv6:
				skip(p.ID, ReasonOwnAddress, fmt.Errorf("address %s", a))
				continue peers
			}
			op.Addresses = append(op.Addresses, a)
		}
		if len(op.Addresses) == 0 {
			skip(p.ID, ReasonNoAddress, nil)
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
			skip(op.ID, ReasonKeyClaimed, fmt.Errorf("key %s", op.Key))
			continue
		}
		shared := false
		for _, a := range op.Addresses {
			if claims[a] > 1 {
				skip(op.ID, ReasonAddressClaimed, fmt.Errorf("address %s", a))
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
