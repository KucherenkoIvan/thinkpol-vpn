package netmap

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/shaping"
	netmapv1 "github.com/KucherenkoIvan/thinkpol-vpn/proto/gen/thinkpol/netmap/v1"
)

// SectionReader is the section reader this package implements. Build marks
// every section with the lowest reader that understands it, and Open
// refuses sections that need a newer one. Raise it, and mark the sections
// that use a new field, when older nodes must not silently ignore the field.
// A node that refuses its section keeps its last map and stops taking newer
// ones (revocations included), so a field whose absence fails open (a node
// admitting what it shouldn't) is better kept out of the map by Build than
// left to newer readers: ingress is (devices' links to a server with
// ingress off are never written).
//
// Routing rules, chains and rule presets don't raise it: a node too old to
// know them ignores them and routes nothing outside the overlay, so its
// internet traffic never enters the tunnel, as on M0. Marking them would
// prevent no leak and would freeze such nodes on their last map, with its
// revocations.
const SectionReader = 1

// Section is one node's need-to-know part of the map: its own settings and
// the nodes it talks to, every one known by an opaque id. New needs (rules,
// guest spaces, telemetry) are new fields here and in the schema.
type Section struct {
	// MinReader is the reader level the section was marked with, as Open
	// read it (for inspection). Build ignores it: it marks every section
	// itself.
	MinReader uint32

	Node NodeSettings
	// Peers are end-to-end WireGuard peers.
	Peers []Peer
	// Links are adjacent nodes this node dials.
	Links []Link
	// Inbound are adjacent nodes allowed to connect to this node's listeners.
	Inbound []InboundLink
	// Routes are the forwarding table for relayed packets.
	Routes []Route
	// Blobs are the blobs this node uses, named; each is in the header.
	Blobs []BlobRef
	// Rules are the space's default routing rules, in order: the first
	// that matches a destination decides it. A device may override them
	// locally (dataplane/rules).
	Rules []Rule
	// Chains are the chains rules send traffic through.
	Chains []Chain
	// Presets are what a device's rule presets are built from.
	Presets RulePresets
}

// NodeKind is what a node is: a server (a VPS that relays) or a device.
type NodeKind uint8

const (
	NodeServer NodeKind = iota + 1
	NodeDevice
)

func (k NodeKind) known() bool { return k == NodeServer || k == NodeDevice }

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
	// The space's overlay ranges: inside 100.64.0.0/10, and a ULA /48.
	IPv4Network, IPv6Network netip.Prefix
	// Listeners are the transports this node listens on.
	Listeners []Listener
	// AllowIngress lets devices connect to this server, so it can start a
	// chain. With it off, Build keeps every link between it and devices out
	// of the map, its address out of devices' sections, and the node itself
	// accepts only other servers' inbound links (AcceptsInbound).
	// AllowEgress lets internet traffic leave the space from this server,
	// so it can end a chain. Both are server settings, off by default.
	AllowIngress, AllowEgress bool
}

// AcceptsInbound reports whether a node with these settings accepts the
// inbound link in: a server with ingress off accepts only other servers,
// whatever its section lists (Build never lists devices there; readers
// check anyway, and a guest space's map is not the node owner's to trust).
// Devices have no ingress setting.
func (n *NodeSettings) AcceptsInbound(in InboundLink) bool {
	return n.Kind != NodeServer || n.AllowIngress || in.PeerKind == NodeServer
}

// Listener is a transport a node listens on.
type Listener struct {
	Transport string
	// Address is the IP and port to bind; an unspecified IP (0.0.0.0, ::)
	// binds every address of its family.
	Address netip.AddrPort
	// Settings are transport-owned (camouflage target, certificate source),
	// encoded by the transport.
	Settings []byte
}

// Peer is an end-to-end WireGuard peer.
type Peer struct {
	ID           NodeID
	WireGuardKey WireGuardKey
	// Addresses are the peer's overlay addresses.
	Addresses []netip.Addr
	// Paths are the candidate paths to the peer in priority order, which is
	// the order failover follows.
	Paths []Path
}

// Path is a candidate way to reach a peer, named by its first hop: an
// adjacent node, or the peer itself for a direct link. Relays route the
// rest of the way by destination; no node holds a whole path.
type Path struct {
	FirstHop NodeID
}

// Link is an adjacent node this node dials.
type Link struct {
	Peer NodeID
	// Endpoints are the ways to reach the peer, in priority order.
	Endpoints []Endpoint
}

// Endpoint is one way to reach an adjacent node.
type Endpoint struct {
	Transport string
	// Address is the IP and port to dial. Never a host name: the controller
	// resolves names, so nodes never ask DNS at dial time, past the tunnel.
	Address netip.AddrPort
	// Credential is the transport-specific credential for this link.
	Credential []byte
	// Settings are transport-owned (certificate pin, SNI, WebSocket path),
	// encoded by the transport.
	Settings []byte
	// Shaping is how this node shapes what it sends on the link, an
	// encoded thinkpol.transport.v1.Shaping (empty for none) that the
	// data-plane engine decodes.
	Shaping []byte
}

// InboundLink lets an adjacent node connect to this node's listener for a
// transport.
type InboundLink struct {
	Peer     NodeID
	PeerKind NodeKind
	// Transport names the listener.
	Transport string
	// Credential is the transport's verifier for the peer's credential: a
	// hash or public key where the transport allows, so a seized node can't
	// impersonate its peers; for a symmetric transport, the shared secret.
	Credential []byte
	// Settings are transport-owned settings for this link, encoded by the
	// transport.
	Settings []byte
	// Shaping is how this node shapes what it sends on the link, as on an
	// Endpoint.
	Shaping []byte
}

// Route sends relayed packets for Destination to an adjacent next hop.
type Route struct {
	Destination NodeID
	// NextHops are adjacent nodes in priority order; several for a hop group
	// in the middle of a chain. A next hop equal to Destination delivers
	// directly.
	NextHops []NodeID
}

const (
	maxTransportName = 32
	maxCredential    = 1024
	maxSettings      = 4096
)

var (
	cgnat = netip.MustParsePrefix("100.64.0.0/10")
	ula   = netip.MustParsePrefix("fd00::/8") // RFC 4193, locally assigned
)

// errUnknownKind makes Open report a section for a node kind this reader
// doesn't know as a format it doesn't support.
var errUnknownKind = fmt.Errorf("%w: unknown node kind", ErrUnsupportedFormat)

// wellFormed is what every reader checks: a section a node can use without
// tripping over itself. Ids are set, nothing names the node itself where it
// can't, and keyed lists have no repeated keys. Lengths and canonical
// encodings are checked when decoding. Policy is Build's (see validate).
func (s *Section) wellFormed() error {
	self := s.Node.ID
	if self.IsZero() {
		return errors.New("node id is zero")
	}
	switch {
	case s.Node.Kind == 0:
		return errors.New("node kind unspecified")
	case !s.Node.Kind.known():
		return fmt.Errorf("%w %d", errUnknownKind, s.Node.Kind)
	}
	other := func(what string, id NodeID) error {
		if id.IsZero() {
			return fmt.Errorf("%s: node id is zero", what)
		}
		if id == self {
			return fmt.Errorf("%s: names the node itself", what)
		}
		return nil
	}

	peers := make(map[NodeID]bool, len(s.Peers))
	for _, p := range s.Peers {
		if err := other("peer", p.ID); err != nil {
			return err
		}
		if peers[p.ID] {
			return fmt.Errorf("peer %v listed twice", p.ID)
		}
		peers[p.ID] = true
		for _, path := range p.Paths {
			if err := other("path", path.FirstHop); err != nil {
				return fmt.Errorf("peer %v: %w", p.ID, err)
			}
		}
	}
	links := make(map[NodeID]bool, len(s.Links))
	for _, l := range s.Links {
		if err := other("link", l.Peer); err != nil {
			return err
		}
		if links[l.Peer] {
			return fmt.Errorf("link to %v listed twice", l.Peer)
		}
		links[l.Peer] = true
	}
	type inboundKey struct {
		peer      NodeID
		transport string
	}
	inbound := make(map[inboundKey]bool, len(s.Inbound))
	for _, in := range s.Inbound {
		if err := other("inbound link", in.Peer); err != nil {
			return err
		}
		k := inboundKey{in.Peer, in.Transport}
		if inbound[k] {
			return fmt.Errorf("inbound link from %v over %q listed twice", in.Peer, in.Transport)
		}
		inbound[k] = true
	}
	routes := make(map[NodeID]bool, len(s.Routes))
	for _, r := range s.Routes {
		if err := other("route", r.Destination); err != nil {
			return err
		}
		if routes[r.Destination] {
			return fmt.Errorf("route to %v listed twice", r.Destination)
		}
		routes[r.Destination] = true
		hops := make(map[NodeID]bool, len(r.NextHops))
		for _, h := range r.NextHops {
			if err := other("next hop", h); err != nil {
				return fmt.Errorf("route to %v: %w", r.Destination, err)
			}
			if hops[h] {
				return fmt.Errorf("route to %v: next hop %v listed twice", r.Destination, h)
			}
			hops[h] = true
		}
	}
	if err := s.rulesWellFormed(); err != nil {
		return err
	}
	return blobsWellFormed(s.Blobs)
}

func blobsWellFormed(blobs []BlobRef) error {
	seen := make(map[[32]byte]bool, len(blobs))
	for _, b := range blobs {
		if b.SHA256 == ([32]byte{}) || seen[b.SHA256] {
			return fmt.Errorf("blob %x zero or repeated", b.SHA256)
		}
		if b.Size == 0 {
			return fmt.Errorf("blob %x of size 0", b.SHA256)
		}
		seen[b.SHA256] = true
	}
	return nil
}

// validate is Build's check: well-formed, plus the policy and consistency a
// map builder must keep. Readers don't repeat it, so it can tighten without
// breaking maps already out there.
func (s *Section) validate(headerBlobs []BlobRef) error {
	if err := s.wellFormed(); err != nil {
		return err
	}
	n := &s.Node
	if !n.IPv4Network.IsValid() || !n.IPv4Network.Addr().Is4() || n.IPv4Network != n.IPv4Network.Masked() ||
		!cgnat.Contains(n.IPv4Network.Addr()) || n.IPv4Network.Bits() < cgnat.Bits() {
		return fmt.Errorf("IPv4 network %v is not a prefix inside %v", n.IPv4Network, cgnat)
	}
	if !n.IPv6Network.IsValid() || !n.IPv6Network.Addr().Is6() || n.IPv6Network.Addr().Is4In6() ||
		n.IPv6Network != n.IPv6Network.Masked() || !ula.Contains(n.IPv6Network.Addr()) || n.IPv6Network.Bits() != 48 {
		return fmt.Errorf("IPv6 network %v is not a /48 inside %v", n.IPv6Network, ula)
	}
	if !n.IPv4Network.Contains(n.IPv4) || !n.IPv6Network.Contains(n.IPv6) {
		return fmt.Errorf("node addresses %v, %v are outside the overlay networks", n.IPv4, n.IPv6)
	}
	inOverlay := func(a netip.Addr) bool { return n.IPv4Network.Contains(a) || n.IPv6Network.Contains(a) }
	if n.Kind != NodeServer && (n.AllowIngress || n.AllowEgress) {
		return errors.New("ingress and egress are server settings")
	}
	// Devices don't listen until direct paths between devices exist: a
	// device's listener would take links the ingress rules don't cover.
	if n.Kind == NodeDevice && len(n.Listeners) > 0 {
		return errors.New("a device has no listeners")
	}

	type transportAddr struct {
		transport string
		address   netip.AddrPort
	}
	listeners := make(map[transportAddr]bool, len(n.Listeners))
	for _, l := range n.Listeners {
		if err := checkTransport(l.Transport); err != nil {
			return fmt.Errorf("listener: %w", err)
		}
		if err := checkAddrPort(l.Address); err != nil {
			return fmt.Errorf("listener: %w", err)
		}
		if err := checkSettings(l.Settings); err != nil {
			return fmt.Errorf("listener: %w", err)
		}
		k := transportAddr{l.Transport, l.Address}
		if listeners[k] {
			return fmt.Errorf("listener %s %s listed twice", l.Transport, l.Address)
		}
		listeners[k] = true
	}

	adjacent := make(map[NodeID]bool, len(s.Links)+len(s.Inbound))
	for _, l := range s.Links {
		adjacent[l.Peer] = true
		if len(l.Endpoints) == 0 {
			return fmt.Errorf("link to %v: no endpoints", l.Peer)
		}
		endpoints := make(map[transportAddr]bool, len(l.Endpoints))
		for _, e := range l.Endpoints {
			if err := checkTransport(e.Transport); err != nil {
				return fmt.Errorf("link to %v: %w", l.Peer, err)
			}
			if err := checkAddrPort(e.Address); err != nil {
				return fmt.Errorf("link to %v: %w", l.Peer, err)
			}
			if e.Address.Addr().IsUnspecified() {
				return fmt.Errorf("link to %v: endpoint %v has no address to dial", l.Peer, e.Address)
			}
			if err := checkCredential(e.Credential); err != nil {
				return fmt.Errorf("link to %v: %w", l.Peer, err)
			}
			if err := checkSettings(e.Settings, e.Shaping); err != nil {
				return fmt.Errorf("link to %v: %w", l.Peer, err)
			}
			k := transportAddr{e.Transport, e.Address}
			if endpoints[k] {
				return fmt.Errorf("link to %v: endpoint %s %s listed twice", l.Peer, e.Transport, e.Address)
			}
			endpoints[k] = true
		}
	}
	// A listener maps a credential to a peer; two peers with one credential
	// on one transport would be indistinguishable.
	type transportCredential struct{ transport, credential string }
	credentials := make(map[transportCredential]bool, len(s.Inbound))
	for _, in := range s.Inbound {
		adjacent[in.Peer] = true
		if !in.PeerKind.known() {
			return fmt.Errorf("inbound link from %v: peer kind %v", in.Peer, in.PeerKind)
		}
		if !n.AcceptsInbound(in) {
			return fmt.Errorf("inbound link from %v: a %v's, on a server with ingress off", in.Peer, in.PeerKind)
		}
		if err := checkTransport(in.Transport); err != nil {
			return fmt.Errorf("inbound link from %v: %w", in.Peer, err)
		}
		if err := checkCredential(in.Credential); err != nil {
			return fmt.Errorf("inbound link from %v: %w", in.Peer, err)
		}
		if err := checkSettings(in.Settings, in.Shaping); err != nil {
			return fmt.Errorf("inbound link from %v: %w", in.Peer, err)
		}
		k := transportCredential{in.Transport, string(in.Credential)}
		if credentials[k] {
			return fmt.Errorf("inbound link from %v: credential shared with another peer on %s", in.Peer, in.Transport)
		}
		credentials[k] = true
	}

	addresses := map[netip.Addr]bool{n.IPv4: true, n.IPv6: true}
	for _, p := range s.Peers {
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
			if addresses[a] {
				return fmt.Errorf("peer %v: address %v is taken", p.ID, a)
			}
			addresses[a] = true
		}
		if len(p.Paths) == 0 {
			return fmt.Errorf("peer %v: no paths", p.ID)
		}
		hops := make(map[NodeID]bool, len(p.Paths))
		for _, path := range p.Paths {
			if !adjacent[path.FirstHop] {
				return fmt.Errorf("peer %v: first hop %v is not adjacent", p.ID, path.FirstHop)
			}
			if hops[path.FirstHop] {
				return fmt.Errorf("peer %v: first hop %v listed twice", p.ID, path.FirstHop)
			}
			hops[path.FirstHop] = true
		}
	}
	for _, r := range s.Routes {
		if len(r.NextHops) == 0 {
			return fmt.Errorf("route to %v: no next hops", r.Destination)
		}
		for _, h := range r.NextHops {
			if !adjacent[h] {
				return fmt.Errorf("route to %v: next hop %v is not adjacent", r.Destination, h)
			}
		}
	}

	available := make(map[[32]byte]BlobRef, len(headerBlobs))
	for _, b := range headerBlobs {
		available[b.SHA256] = b
	}
	for _, b := range s.Blobs {
		h, ok := available[b.SHA256]
		if !ok || h.Kind != b.Kind || h.Size != b.Size {
			return fmt.Errorf("blob %x is not in the header", b.SHA256)
		}
	}
	return s.validateRules()
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

// checkAddrPort is the builder's rule for addresses: an IP literal (no
// zone, no IPv4-mapped IPv6) and a non-zero port.
func checkAddrPort(a netip.AddrPort) error {
	ip := a.Addr()
	if !ip.IsValid() || ip.Zone() != "" || ip.Is4In6() || a.Port() == 0 {
		return fmt.Errorf("address %v is not an IP and a port", a)
	}
	return nil
}

func checkCredential(c []byte) error {
	if len(c) == 0 || len(c) > maxCredential {
		return fmt.Errorf("credential of %d bytes", len(c))
	}
	return nil
}

// checkSettings bounds transport-owned bytes: settings, and shaping where
// there is one. Shaping must also decode under internal/shaping's rules
// (the same the transport port applies), so the builder never publishes
// shaping that every node would refuse.
func checkSettings(settings []byte, shapingBytes ...[]byte) error {
	if len(settings) > maxSettings {
		return fmt.Errorf("transport settings of %d bytes", len(settings))
	}
	for _, b := range shapingBytes {
		if len(b) > maxSettings {
			return fmt.Errorf("shaping of %d bytes", len(b))
		}
		if len(b) == 0 {
			continue
		}
		if _, err := shaping.Decode(b); err != nil {
			return fmt.Errorf("shaping: %w", err)
		}
	}
	return nil
}

func sectionToProto(s *Section, h *Header) *netmapv1.Section {
	pb := &netmapv1.Section{
		MinReader:  SectionReader,
		SpaceId:    h.SpaceID[:],
		KeyEpoch:   h.KeyEpoch,
		MapVersion: h.Version,
		Node: &netmapv1.NodeSettings{
			Id:           idBytes(s.Node.ID),
			Kind:         netmapv1.NodeKind(s.Node.Kind),
			Ipv4:         addrString(s.Node.IPv4),
			Ipv6:         addrString(s.Node.IPv6),
			Ipv4Network:  prefixString(s.Node.IPv4Network),
			Ipv6Network:  prefixString(s.Node.IPv6Network),
			AllowIngress: s.Node.AllowIngress,
			AllowEgress:  s.Node.AllowEgress,
		},
		Blobs: blobsToProto(s.Blobs),
	}
	for _, l := range s.Node.Listeners {
		pb.Node.Listeners = append(pb.Node.Listeners, &netmapv1.Listener{Transport: l.Transport, Address: addrPortString(l.Address), Settings: l.Settings})
	}
	for _, p := range s.Peers {
		pp := &netmapv1.Peer{Id: idBytes(p.ID), WireguardPublicKey: p.WireGuardKey[:]}
		for _, a := range p.Addresses {
			pp.Addresses = append(pp.Addresses, addrString(a))
		}
		for _, path := range p.Paths {
			pp.Paths = append(pp.Paths, &netmapv1.Path{FirstHop: idBytes(path.FirstHop)})
		}
		pb.Peers = append(pb.Peers, pp)
	}
	for _, l := range s.Links {
		pl := &netmapv1.Link{Peer: idBytes(l.Peer)}
		for _, e := range l.Endpoints {
			pl.Endpoints = append(pl.Endpoints, &netmapv1.Endpoint{
				Transport: e.Transport, Address: addrPortString(e.Address), Credential: e.Credential, Settings: e.Settings, Shaping: e.Shaping,
			})
		}
		pb.Links = append(pb.Links, pl)
	}
	for _, in := range s.Inbound {
		pb.Inbound = append(pb.Inbound, &netmapv1.InboundLink{
			Peer: idBytes(in.Peer), PeerKind: netmapv1.NodeKind(in.PeerKind), Transport: in.Transport,
			Credential: in.Credential, Settings: in.Settings, Shaping: in.Shaping,
		})
	}
	for _, r := range s.Routes {
		pb.Routes = append(pb.Routes, &netmapv1.Route{Destination: idBytes(r.Destination), NextHops: idsBytes(r.NextHops)})
	}
	rulesToProto(s, pb)
	return pb
}

// sectionFromProto decodes strictly: every id and key has its exact length
// and every address its canonical text form, so a section has one encoding.
// The caller checks wellFormed.
func sectionFromProto(pb *netmapv1.Section) (Section, error) {
	var s Section
	n := pb.GetNode()
	if n == nil {
		return s, errors.New("no node settings")
	}
	var err error
	if s.Node.ID, err = toArray[NodeID]("node id", n.GetId()); err != nil {
		return s, err
	}
	if s.Node.Kind, err = kindFromProto(n.GetKind()); err != nil {
		return s, err
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
	s.Node.AllowIngress, s.Node.AllowEgress = n.GetAllowIngress(), n.GetAllowEgress()
	for _, l := range n.GetListeners() {
		addr, err := parseAddrPort(l.GetAddress())
		if err != nil {
			return s, fmt.Errorf("listener: %w", err)
		}
		s.Node.Listeners = append(s.Node.Listeners, Listener{Transport: l.GetTransport(), Address: addr, Settings: l.GetSettings()})
	}
	for _, pp := range pb.GetPeers() {
		var p Peer
		if p.ID, err = toArray[NodeID]("peer id", pp.GetId()); err != nil {
			return s, err
		}
		if p.WireGuardKey, err = toArray[WireGuardKey]("WireGuard key", pp.GetWireguardPublicKey()); err != nil {
			return s, err
		}
		for _, a := range pp.GetAddresses() {
			addr, err := parseAddr(a)
			if err != nil || !addr.IsValid() {
				return s, fmt.Errorf("peer %v: address %q", p.ID, a)
			}
			p.Addresses = append(p.Addresses, addr)
		}
		for _, path := range pp.GetPaths() {
			hop, err := toArray[NodeID]("first hop", path.GetFirstHop())
			if err != nil {
				return s, err
			}
			p.Paths = append(p.Paths, Path{FirstHop: hop})
		}
		s.Peers = append(s.Peers, p)
	}
	for _, pl := range pb.GetLinks() {
		var l Link
		if l.Peer, err = toArray[NodeID]("link peer", pl.GetPeer()); err != nil {
			return s, err
		}
		for _, e := range pl.GetEndpoints() {
			addr, err := parseAddrPort(e.GetAddress())
			if err != nil {
				return s, fmt.Errorf("link to %v: %w", l.Peer, err)
			}
			l.Endpoints = append(l.Endpoints, Endpoint{
				Transport: e.GetTransport(), Address: addr, Credential: e.GetCredential(), Settings: e.GetSettings(), Shaping: e.GetShaping(),
			})
		}
		s.Links = append(s.Links, l)
	}
	for _, pin := range pb.GetInbound() {
		in := InboundLink{Transport: pin.GetTransport(), Credential: pin.GetCredential(), Settings: pin.GetSettings(), Shaping: pin.GetShaping()}
		if in.Peer, err = toArray[NodeID]("inbound peer", pin.GetPeer()); err != nil {
			return s, err
		}
		// An unknown peer kind is the builder's concern; a reader keeps it.
		in.PeerKind = NodeKind(min(uint32(pin.GetPeerKind()), 255))
		s.Inbound = append(s.Inbound, in)
	}
	for _, pr := range pb.GetRoutes() {
		var r Route
		if r.Destination, err = toArray[NodeID]("route destination", pr.GetDestination()); err != nil {
			return s, err
		}
		if r.NextHops, err = toIDs(pr.GetNextHops()); err != nil {
			return s, err
		}
		s.Routes = append(s.Routes, r)
	}
	if s.Blobs, err = blobsFromProto(pb.GetBlobs()); err != nil {
		return s, err
	}
	if err := rulesFromProto(pb, &s); err != nil {
		return s, err
	}
	return s, nil
}

func kindFromProto(k netmapv1.NodeKind) (NodeKind, error) {
	if k < 0 || k > 255 {
		return 0, fmt.Errorf("%w %d", errUnknownKind, k)
	}
	return NodeKind(k), nil
}

func blobsToProto(blobs []BlobRef) []*netmapv1.BlobRef {
	var out []*netmapv1.BlobRef
	for _, b := range blobs {
		out = append(out, &netmapv1.BlobRef{Kind: netmapv1.BlobKind(b.Kind), Sha256: b.SHA256[:], Size: b.Size, Name: b.Name})
	}
	return out
}

func blobsFromProto(pbs []*netmapv1.BlobRef) ([]BlobRef, error) {
	var out []BlobRef
	for _, pb := range pbs {
		sum, err := toArray[[32]byte]("blob hash", pb.GetSha256())
		if err != nil {
			return nil, err
		}
		// An unknown blob kind is kept: relays cache blobs of any kind.
		out = append(out, BlobRef{Kind: BlobKind(min(uint32(pb.GetKind()), 255)), SHA256: sum, Size: pb.GetSize(), Name: pb.GetName()})
	}
	return out, nil
}

func idBytes(id NodeID) []byte { return id[:] }

func idsBytes(ids []NodeID) [][]byte {
	var out [][]byte
	for _, id := range ids {
		out = append(out, idBytes(id))
	}
	return out
}

func toArray[T ~[8]byte | ~[16]byte | ~[32]byte](what string, b []byte) (T, error) {
	var v T
	if len(b) != len(v) {
		return v, fmt.Errorf("%s of %d bytes, want %d", what, len(b), len(v))
	}
	return T(b), nil
}

func toIDs(bs [][]byte) ([]NodeID, error) {
	var out []NodeID
	for _, b := range bs {
		id, err := toArray[NodeID]("node id", b)
		if err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, nil
}

// An invalid address or prefix is encoded as the empty string and decodes
// back to the zero value; Build's policy rejects it where it is required.
func addrString(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func prefixString(p netip.Prefix) string {
	if !p.IsValid() {
		return ""
	}
	return p.String()
}

func parseAddr(s string) (netip.Addr, error) {
	if s == "" {
		return netip.Addr{}, nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.String() != s || a.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("address %q is not in canonical form", s)
	}
	return a, nil
}

func addrPortString(a netip.AddrPort) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

// parseAddrPort accepts only ip:port in canonical text form, so a host name
// can't reach a node through its map.
func parseAddrPort(s string) (netip.AddrPort, error) {
	if s == "" {
		return netip.AddrPort{}, nil
	}
	a, err := netip.ParseAddrPort(s)
	if err != nil || a.String() != s || a.Addr().Zone() != "" {
		return netip.AddrPort{}, fmt.Errorf("address %q is not an IP and port in canonical form", s)
	}
	return a, nil
}

func parsePrefix(s string) (netip.Prefix, error) {
	if s == "" {
		return netip.Prefix{}, nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil || p.String() != s {
		return netip.Prefix{}, fmt.Errorf("prefix %q is not in canonical form", s)
	}
	return p, nil
}
