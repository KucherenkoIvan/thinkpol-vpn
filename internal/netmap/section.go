package netmap

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	netmapv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/netmap/v1"
)

// Section is one node's need-to-know part of the map: its own settings and
// the nodes it talks to, every one known by an opaque id. New needs (ingress
// and egress settings, rules, guest spaces, telemetry) are new fields here
// and in the schema.
type Section struct {
	Node NodeSettings
	// Peers are end-to-end WireGuard peers.
	Peers []Peer
	// Links are adjacent nodes this node dials.
	Links []Link
	// Inbound are adjacent nodes allowed to connect to this node's listeners.
	Inbound []InboundLink
	// RelayTo are the node ids this node may forward relayed packets to.
	RelayTo []NodeID
}

// NodeKind is what a node is: a server (a VPS that relays) or a device.
type NodeKind uint8

const (
	NodeServer NodeKind = iota + 1
	NodeDevice
)

func (k NodeKind) String() string {
	switch k {
	case NodeServer:
		return "server"
	case NodeDevice:
		return "device"
	}
	return "NodeKind(" + strconv.Itoa(int(k)) + ")"
}

// NodeSettings are the recipient node's own settings.
type NodeSettings struct {
	ID   NodeID
	Kind NodeKind
	// The node's overlay addresses.
	IPv4, IPv6 netip.Addr
	// The space's overlay ranges: inside 100.64.0.0/10 and inside the ULA
	// range fc00::/7.
	IPv4Network, IPv6Network netip.Prefix
	// Listeners are the transports this node listens on.
	Listeners []Listener
}

// Listener is a transport a node listens on.
type Listener struct {
	Transport string
	// Address is host:port to bind; an empty host binds every address.
	Address string
}

// Peer is an end-to-end WireGuard peer.
type Peer struct {
	ID           NodeID
	WireGuardKey WireGuardKey
	// Addresses are the peer's overlay addresses, its WireGuard allowed IPs.
	Addresses []netip.Addr
	// Paths are the candidate paths to the peer; at least one.
	Paths []Path
}

// Path is the relays a packet crosses to reach a peer, in order. No relays
// means a direct link to the peer.
type Path struct {
	Via []NodeID
}

// Link is an adjacent node this node dials.
type Link struct {
	Peer NodeID
	// Endpoints are the ways to reach the peer, in order of preference.
	Endpoints []Endpoint
}

// Endpoint is one way to reach an adjacent node.
type Endpoint struct {
	Transport string
	// Address is host:port to dial.
	Address string
	// Credential is the transport-specific credential for this link.
	Credential []byte
}

// InboundLink lets an adjacent node connect to this node's listener for a
// transport, with a credential.
type InboundLink struct {
	Peer       NodeID
	Transport  string
	Credential []byte
}

const (
	maxTransportName = 32
	maxCredential    = 1024
)

var (
	cgnat = netip.MustParsePrefix("100.64.0.0/10")
	ula   = netip.MustParsePrefix("fc00::/7")
)

// validate checks that s is well formed. Policy (which node may know what)
// is the map builder's job, not the format's.
func (s *Section) validate() error {
	n := &s.Node
	if n.ID.IsZero() {
		return errors.New("node id is zero")
	}
	if n.Kind != NodeServer && n.Kind != NodeDevice {
		return fmt.Errorf("node kind %v", n.Kind)
	}
	if !n.IPv4Network.IsValid() || !n.IPv4Network.Addr().Is4() || n.IPv4Network != n.IPv4Network.Masked() ||
		!cgnat.Contains(n.IPv4Network.Addr()) || n.IPv4Network.Bits() < cgnat.Bits() {
		return fmt.Errorf("IPv4 network %v is not a prefix inside %v", n.IPv4Network, cgnat)
	}
	if !n.IPv6Network.IsValid() || !n.IPv6Network.Addr().Is6() || n.IPv6Network.Addr().Is4In6() ||
		n.IPv6Network != n.IPv6Network.Masked() || !ula.Contains(n.IPv6Network.Addr()) || n.IPv6Network.Bits() < ula.Bits() {
		return fmt.Errorf("IPv6 network %v is not a prefix inside %v", n.IPv6Network, ula)
	}
	if !n.IPv4Network.Contains(n.IPv4) || !n.IPv6Network.Contains(n.IPv6) {
		return fmt.Errorf("node addresses %v, %v are outside the overlay networks", n.IPv4, n.IPv6)
	}
	inOverlay := func(a netip.Addr) bool { return n.IPv4Network.Contains(a) || n.IPv6Network.Contains(a) }
	for _, l := range n.Listeners {
		if err := checkTransport(l.Transport); err != nil {
			return fmt.Errorf("listener: %w", err)
		}
		if err := checkHostPort(l.Address, true); err != nil {
			return fmt.Errorf("listener: %w", err)
		}
	}

	notSelf := func(what string, id NodeID) error {
		if id.IsZero() {
			return fmt.Errorf("%s: node id is zero", what)
		}
		if id == n.ID {
			return fmt.Errorf("%s: names the node itself", what)
		}
		return nil
	}

	peers := make(map[NodeID]bool, len(s.Peers))
	for _, p := range s.Peers {
		if err := notSelf("peer", p.ID); err != nil {
			return err
		}
		if peers[p.ID] {
			return fmt.Errorf("peer %v listed twice", p.ID)
		}
		peers[p.ID] = true
		if p.WireGuardKey.IsZero() {
			return fmt.Errorf("peer %v: WireGuard key is zero", p.ID)
		}
		if len(p.Addresses) == 0 {
			return fmt.Errorf("peer %v: no addresses", p.ID)
		}
		for _, a := range p.Addresses {
			if !inOverlay(a) {
				return fmt.Errorf("peer %v: address %v is outside the overlay networks", p.ID, a)
			}
		}
		if len(p.Paths) == 0 {
			return fmt.Errorf("peer %v: no paths", p.ID)
		}
		for _, path := range p.Paths {
			seen := make(map[NodeID]bool, len(path.Via))
			for _, hop := range path.Via {
				if err := notSelf("path", hop); err != nil {
					return fmt.Errorf("peer %v: %w", p.ID, err)
				}
				if hop == p.ID || seen[hop] {
					return fmt.Errorf("peer %v: path crosses %v twice", p.ID, hop)
				}
				seen[hop] = true
			}
		}
	}

	links := make(map[NodeID]bool, len(s.Links))
	for _, l := range s.Links {
		if err := notSelf("link", l.Peer); err != nil {
			return err
		}
		if links[l.Peer] {
			return fmt.Errorf("link to %v listed twice", l.Peer)
		}
		links[l.Peer] = true
		if len(l.Endpoints) == 0 {
			return fmt.Errorf("link to %v: no endpoints", l.Peer)
		}
		for _, e := range l.Endpoints {
			if err := checkTransport(e.Transport); err != nil {
				return fmt.Errorf("link to %v: %w", l.Peer, err)
			}
			if err := checkHostPort(e.Address, false); err != nil {
				return fmt.Errorf("link to %v: %w", l.Peer, err)
			}
			if err := checkCredential(e.Credential); err != nil {
				return fmt.Errorf("link to %v: %w", l.Peer, err)
			}
		}
	}

	type inboundKey struct {
		peer      NodeID
		transport string
	}
	inbound := make(map[inboundKey]bool, len(s.Inbound))
	for _, a := range s.Inbound {
		if err := notSelf("inbound link", a.Peer); err != nil {
			return err
		}
		if err := checkTransport(a.Transport); err != nil {
			return fmt.Errorf("inbound link from %v: %w", a.Peer, err)
		}
		if err := checkCredential(a.Credential); err != nil {
			return fmt.Errorf("inbound link from %v: %w", a.Peer, err)
		}
		k := inboundKey{a.Peer, a.Transport}
		if inbound[k] {
			return fmt.Errorf("inbound link from %v over %s listed twice", a.Peer, a.Transport)
		}
		inbound[k] = true
	}

	relay := make(map[NodeID]bool, len(s.RelayTo))
	for _, id := range s.RelayTo {
		if err := notSelf("relay destination", id); err != nil {
			return err
		}
		if relay[id] {
			return fmt.Errorf("relay destination %v listed twice", id)
		}
		relay[id] = true
	}
	return nil
}

func checkTransport(name string) error {
	if name == "" || len(name) > maxTransportName {
		return fmt.Errorf("transport name %q", name)
	}
	for i, c := range name {
		if c >= 'a' && c <= 'z' || i > 0 && (c >= '0' && c <= '9' || c == '-') {
			continue
		}
		return fmt.Errorf("transport name %q", name)
	}
	return nil
}

func checkHostPort(addr string, hostOptional bool) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("address %q: %w", addr, err)
	}
	if host == "" && !hostOptional {
		return fmt.Errorf("address %q has no host", addr)
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil || p == 0 || strconv.FormatUint(p, 10) != port {
		return fmt.Errorf("address %q: bad port", addr)
	}
	return nil
}

func checkCredential(c []byte) error {
	if len(c) == 0 || len(c) > maxCredential {
		return fmt.Errorf("credential of %d bytes", len(c))
	}
	return nil
}

func sectionToProto(s *Section, space SpaceID, version uint64) *netmapv1.Section {
	pb := &netmapv1.Section{
		SpaceId:    space[:],
		MapVersion: version,
		Node: &netmapv1.NodeSettings{
			Id:          idBytes(s.Node.ID),
			Kind:        netmapv1.NodeKind(s.Node.Kind),
			Ipv4:        s.Node.IPv4.String(),
			Ipv6:        s.Node.IPv6.String(),
			Ipv4Network: s.Node.IPv4Network.String(),
			Ipv6Network: s.Node.IPv6Network.String(),
		},
	}
	for _, l := range s.Node.Listeners {
		pb.Node.Listeners = append(pb.Node.Listeners, &netmapv1.Listener{Transport: l.Transport, Address: l.Address})
	}
	for _, p := range s.Peers {
		pp := &netmapv1.Peer{Id: idBytes(p.ID), WireguardPublicKey: p.WireGuardKey[:]}
		for _, a := range p.Addresses {
			pp.Addresses = append(pp.Addresses, a.String())
		}
		for _, path := range p.Paths {
			pp.Paths = append(pp.Paths, &netmapv1.Path{Via: idsBytes(path.Via)})
		}
		pb.Peers = append(pb.Peers, pp)
	}
	for _, l := range s.Links {
		pl := &netmapv1.Link{Peer: idBytes(l.Peer)}
		for _, e := range l.Endpoints {
			pl.Endpoints = append(pl.Endpoints, &netmapv1.Endpoint{Transport: e.Transport, Address: e.Address, Credential: e.Credential})
		}
		pb.Links = append(pb.Links, pl)
	}
	for _, a := range s.Inbound {
		pb.Inbound = append(pb.Inbound, &netmapv1.InboundLink{Peer: idBytes(a.Peer), Transport: a.Transport, Credential: a.Credential})
	}
	pb.RelayTo = idsBytes(s.RelayTo)
	return pb
}

// sectionFromProto converts a decoded section strictly: every id and key has
// its exact length and every address its canonical text form, so a section
// has one encoding. It doesn't validate; the caller does.
func sectionFromProto(pb *netmapv1.Section) (Section, error) {
	var s Section
	n := pb.GetNode()
	if n == nil {
		return s, errors.New("no node settings")
	}
	var err error
	if s.Node.ID, err = toID[NodeID]("node id", n.GetId()); err != nil {
		return s, err
	}
	s.Node.Kind = NodeKind(n.GetKind())
	if int32(s.Node.Kind) != int32(n.GetKind()) {
		return s, fmt.Errorf("node kind %d", n.GetKind())
	}
	if s.Node.IPv4, err = parseAddr(n.GetIpv4()); err != nil {
		return s, err
	}
	if s.Node.IPv6, err = parseAddr(n.GetIpv6()); err != nil {
		return s, err
	}
	if s.Node.IPv4Network, err = parsePrefix(n.GetIpv4Network()); err != nil {
		return s, err
	}
	if s.Node.IPv6Network, err = parsePrefix(n.GetIpv6Network()); err != nil {
		return s, err
	}
	for _, l := range n.GetListeners() {
		s.Node.Listeners = append(s.Node.Listeners, Listener{Transport: l.GetTransport(), Address: l.GetAddress()})
	}
	for _, pp := range pb.GetPeers() {
		var p Peer
		if p.ID, err = toID[NodeID]("peer id", pp.GetId()); err != nil {
			return s, err
		}
		if p.WireGuardKey, err = toID[WireGuardKey]("WireGuard key", pp.GetWireguardPublicKey()); err != nil {
			return s, err
		}
		for _, a := range pp.GetAddresses() {
			addr, err := parseAddr(a)
			if err != nil {
				return s, err
			}
			p.Addresses = append(p.Addresses, addr)
		}
		for _, path := range pp.GetPaths() {
			via, err := toIDs(path.GetVia())
			if err != nil {
				return s, err
			}
			p.Paths = append(p.Paths, Path{Via: via})
		}
		s.Peers = append(s.Peers, p)
	}
	for _, pl := range pb.GetLinks() {
		var l Link
		if l.Peer, err = toID[NodeID]("link peer", pl.GetPeer()); err != nil {
			return s, err
		}
		for _, e := range pl.GetEndpoints() {
			l.Endpoints = append(l.Endpoints, Endpoint{Transport: e.GetTransport(), Address: e.GetAddress(), Credential: e.GetCredential()})
		}
		s.Links = append(s.Links, l)
	}
	for _, pa := range pb.GetInbound() {
		a := InboundLink{Transport: pa.GetTransport(), Credential: pa.GetCredential()}
		if a.Peer, err = toID[NodeID]("inbound peer", pa.GetPeer()); err != nil {
			return s, err
		}
		s.Inbound = append(s.Inbound, a)
	}
	if s.RelayTo, err = toIDs(pb.GetRelayTo()); err != nil {
		return s, err
	}
	return s, nil
}

func idBytes(id NodeID) []byte { return id[:] }

func idsBytes(ids []NodeID) [][]byte {
	var out [][]byte
	for _, id := range ids {
		out = append(out, idBytes(id))
	}
	return out
}

func toID[T ~[8]byte | ~[16]byte | ~[32]byte](what string, b []byte) (T, error) {
	var v T
	if len(b) != len(v) {
		return v, fmt.Errorf("%s of %d bytes, want %d", what, len(b), len(v))
	}
	return T(b), nil
}

func toIDs(bs [][]byte) ([]NodeID, error) {
	var out []NodeID
	for _, b := range bs {
		id, err := toID[NodeID]("node id", b)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

func parseAddr(s string) (netip.Addr, error) {
	a, err := netip.ParseAddr(s)
	if err != nil || a.String() != s || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("address %q is not in canonical form", s)
	}
	return a, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	if err != nil || p.String() != s {
		return netip.Prefix{}, fmt.Errorf("prefix %q is not in canonical form", s)
	}
	return p, nil
}
