package dataplane_test

import (
	"bytes"
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/path"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/transporttest"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/udp"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

func udpRegistry(t *testing.T) *transport.Registry {
	t.Helper()
	reg, err := transport.NewRegistry(udp.New(udp.Options{}))
	if err != nil {
		t.Fatal(err)
	}
	return reg
}

func TestOverlayMTU(t *testing.T) {
	reg := udpRegistry(t)
	secret := bytes.Repeat([]byte{7}, udp.MinSecretSize)
	shaped, err := transport.Shaping{Padding: transporttest.Buckets(512, 1200, 1600)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	section := func(dialShaping, acceptShaping []byte) netmap.Section {
		return netmap.Section{
			Node: netmap.NodeSettings{ID: nid(1)},
			Links: []netmap.Link{{Peer: nid(2), Endpoints: []netmap.Endpoint{{
				Transport: "udp", Address: netip.MustParseAddrPort("192.0.2.2:4500"), Credential: secret, Shaping: dialShaping,
			}}}},
			Inbound: []netmap.InboundLink{{Peer: nid(3), Transport: "udp", Credential: secret, Shaping: acceptShaping}},
		}
	}
	mtu := func(s netmap.Section, linkMTU int) int {
		pc, in := dataplane.PathConfigFrom(s, reg), dataplane.InboundFrom(s, reg, transport.SpaceID{9})
		return dataplane.OverlayMTU(&pc, &in, reg, linkMTU)
	}
	// TP-006 and TP-027's figure: 1500 − 48 − 74 (udp) − 18 (path) − 32.
	if got := mtu(section(nil, nil), 0); got != 1328 {
		t.Fatalf("unshaped udp over 1500: %d, want 1328", got)
	}
	// Jumbo links: as much as the path layer carries.
	if got := mtu(section(nil, nil), 9000); got != path.MaxMessageSize-32 {
		t.Fatalf("jumbo links: %d, want %d", got, path.MaxMessageSize-32)
	}
	// Buckets cap what a link carries at the largest bucket that fits
	// (1200), on either end of the node's links.
	for name, s := range map[string]netmap.Section{"dialed": section(shaped, nil), "accepted": section(nil, shaped)} {
		if got, want := mtu(s, 0), 1200-74-18-32; got != want {
			t.Fatalf("%s link shaped: %d, want %d", name, got, want)
		}
	}
	if got := mtu(netmap.Section{Node: netmap.NodeSettings{ID: nid(1)}}, 0); got != 1328 {
		t.Fatalf("no links: %d, want udp's 1328", got)
	}

	// A link that leaves less than the minimum is dropped, not the section.
	tiny, err := transport.Shaping{Padding: transporttest.Buckets(400, 8000)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]netmap.Section{"dialed": section(tiny, nil), "accepted": section(nil, tiny)} {
		pc, in := dataplane.PathConfigFrom(s, reg), dataplane.InboundFrom(s, reg, transport.SpaceID{9})
		if got := dataplane.OverlayMTU(&pc, &in, reg, 0); got != 1328 {
			t.Fatalf("%s link too small: MTU %d, want the other link's 1328", name, got)
		}
		skipped := append(pc.Skipped, in.Skipped...)
		if len(pc.Table.Links)+len(in.Links["udp"]) != 1 || len(skipped) == 0 || skipped[0].Reason != dataplane.ReasonMTUTooSmall {
			t.Fatalf("%s link too small: links %d + %d, skipped %v", name, len(pc.Table.Links), len(in.Links["udp"]), skipped)
		}
	}
}

// AcceptedInbound is what a listener accepts, the engine's and the
// supervisor's alike: the space stamped, and links too small for the
// overlay left out as the engine leaves them out.
func TestAcceptedInbound(t *testing.T) {
	reg := udpRegistry(t)
	tiny, err := transport.Shaping{Padding: transporttest.Buckets(400, 8000)}.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	secret := func(b byte) []byte { return bytes.Repeat([]byte{b}, udp.MinSecretSize) }
	s := netmap.Section{
		Node: netmap.NodeSettings{ID: nid(1)},
		Inbound: []netmap.InboundLink{
			{Peer: nid(2), Transport: "udp", Credential: secret(2)},
			{Peer: nid(3), Transport: "udp", Credential: secret(3), Shaping: tiny},
		},
	}
	in := dataplane.AcceptedInbound(s, reg, transport.SpaceID{9}, 0)
	if len(in.Links["udp"]) != 1 || in.Links["udp"][0].Peer != (transport.Identity{Space: transport.SpaceID{9}, Node: transport.NodeID(nid(2))}) {
		t.Fatalf("accepted %+v", in.Links)
	}
	if len(in.Skipped) != 1 || in.Skipped[0].Reason != dataplane.ReasonMTUTooSmall {
		t.Fatalf("skipped %v", in.Skipped)
	}
}

func overlaySection() netmap.Section {
	return netmap.Section{Node: netmap.NodeSettings{
		ID:          nid(1),
		IPv4:        netip.MustParseAddr("100.64.0.1"),
		IPv6:        netip.MustParseAddr("fd00:1:2::1"),
		IPv4Network: netip.MustParsePrefix("100.64.0.0/16"),
		IPv6Network: netip.MustParsePrefix("fd00:1:2::/48"),
	}}
}

func addrs(ss ...string) []netip.Addr {
	var out []netip.Addr
	for _, s := range ss {
		out = append(out, netip.MustParseAddr(s))
	}
	return out
}

// A section as the map's reader may hand it over: peers the map builder
// would have refused are left out, so WireGuard never holds two peers
// with one allowed IP.
func TestOverlayConfigSkipsPeersItCannotConfigureSafely(t *testing.T) {
	own := netmap.GenerateWireGuardKey().Public()
	key := func() netmap.WireGuardKey { return netmap.GenerateWireGuardKey().Public() }
	shared := key()
	s := overlaySection()
	s.Peers = []netmap.Peer{
		{ID: nid(2), WireGuardKey: key(), Addresses: addrs("100.64.0.2", "fd00:1:2::2")},                    // fine
		{ID: nid(3), WireGuardKey: key(), Addresses: addrs("100.64.0.3", "100.64.0.33")},                    // fine, two IPv4s
		{ID: nid(4), WireGuardKey: key(), Addresses: addrs("100.64.0.4", "100.64.0.5")},                     // collides with 5
		{ID: nid(5), WireGuardKey: key(), Addresses: addrs("100.64.0.5")},                                   // collides with 4
		{ID: nid(6), WireGuardKey: shared, Addresses: addrs("100.64.0.6")},                                  // key shared with 7
		{ID: nid(7), WireGuardKey: shared, Addresses: addrs("100.64.0.7")},                                  // key shared with 6
		{ID: nid(8), WireGuardKey: own, Addresses: addrs("100.64.0.8")},                                     // the node's key
		{ID: nid(9), Addresses: addrs("100.64.0.9")},                                                        // zero key
		{ID: nid(10), WireGuardKey: key(), Addresses: addrs("100.64.0.1")},                                  // the node's address
		{ID: nid(11), WireGuardKey: key(), Addresses: addrs("100.65.0.11")},                                 // outside
		{ID: nid(12), WireGuardKey: key(), Addresses: addrs("fd00:9::12")},                                  // outside
		{ID: nid(13), WireGuardKey: key(), Addresses: addrs("::ffff:100.64.0.13")},                          // mapped: outside
		{ID: nid(14), WireGuardKey: key()},                                                                  // no address
		{ID: nid(1), WireGuardKey: key(), Addresses: addrs("100.64.0.15")},                                  // the node itself
		{ID: nid(16), WireGuardKey: key(), Addresses: []netip.Addr{{}, netip.MustParseAddr("100.64.0.16")}}, // invalid address
	}
	c, err := dataplane.OverlayConfigFrom(s, own, 1328)
	if err != nil {
		t.Fatal(err)
	}
	var ids []byte
	for _, p := range c.Peers {
		ids = append(ids, p.ID[0])
	}
	if !slices.Equal(ids, []byte{2, 3}) {
		t.Fatalf("peers %v, want 2 and 3", ids)
	}
	want := map[byte]dataplane.Reason{
		4: dataplane.ReasonAddressClaimed, 5: dataplane.ReasonAddressClaimed,
		6: dataplane.ReasonKeyClaimed, 7: dataplane.ReasonKeyClaimed,
		8: dataplane.ReasonOwnKey, 9: dataplane.ReasonZeroKey, 10: dataplane.ReasonOwnAddress,
		11: dataplane.ReasonOutsideOverlay, 12: dataplane.ReasonOutsideOverlay, 13: dataplane.ReasonOutsideOverlay,
		14: dataplane.ReasonNoAddress, 1: dataplane.ReasonNotANode, 16: dataplane.ReasonOutsideOverlay,
	}
	if len(c.Skipped) != len(want) {
		t.Fatalf("skipped %d, want %d: %v", len(c.Skipped), len(want), c.Skipped)
	}
	for _, d := range c.Skipped {
		if d.What != dataplane.ItemPeer || want[d.Node[0]] != d.Reason {
			t.Errorf("skip %v, want %v for peer %d", d.Skip, want[d.Node[0]], d.Node[0])
		}
	}
	if c.IPv6Off != nil || len(c.Addrs) != 2 || c.Addrs[0] != netip.MustParsePrefix("100.64.0.1/16") || c.Addrs[1] != netip.MustParsePrefix("fd00:1:2::1/48") {
		t.Fatalf("addresses %v, IPv6 off: %v", c.Addrs, c.IPv6Off)
	}
	if !slices.Equal(c.Networks, []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16"), netip.MustParsePrefix("fd00:1:2::/48")}) {
		t.Fatalf("networks %v", c.Networks)
	}
	if !slices.Equal(c.Local, addrs("100.64.0.1", "fd00:1:2::1")) {
		t.Fatalf("local %v", c.Local)
	}
}

func TestOverlayConfigTurnsIPv6Off(t *testing.T) {
	own := netmap.GenerateWireGuardKey().Public()
	s := overlaySection()
	s.Peers = []netmap.Peer{
		{ID: nid(2), WireGuardKey: netmap.GenerateWireGuardKey().Public(), Addresses: addrs("100.64.0.2", "fd00:1:2::2")},
		{ID: nid(3), WireGuardKey: netmap.GenerateWireGuardKey().Public(), Addresses: addrs("fd00:1:2::3")},
	}
	check := func(name string, s netmap.Section, mtu int, why error) {
		t.Helper()
		c, err := dataplane.OverlayConfigFrom(s, own, mtu)
		if err != nil {
			t.Fatal(err)
		}
		if !errors.Is(c.IPv6Off, why) {
			t.Fatalf("%s: IPv6 off: %v, want %v", name, c.IPv6Off, why)
		}
		if len(c.Addrs) != 1 || len(c.Local) != 1 || len(c.Peers) != 1 || !slices.Equal(c.Peers[0].Addresses, addrs("100.64.0.2")) {
			t.Fatalf("%s: %+v, want IPv4 only, without the IPv6-only peer", name, c)
		}
		// The router still decides the IPv6 network by peers: none.
		if len(c.Networks) != 2 {
			t.Fatalf("%s: networks %v, want both, carried or not", name, c.Networks)
		}
	}
	check("small MTU", s, 1279, dataplane.ErrIPv6MTU)
	noV6 := s
	noV6.Node.IPv6 = netip.Addr{}
	check("no address", noV6, 1328, dataplane.ErrNoIPv6Address)
	outside := s
	outside.Node.IPv6 = netip.MustParseAddr("fd00:9::1")
	check("address outside", outside, 1328, dataplane.ErrNoIPv6Address)
}

func TestOverlayConfigRefusesWhatItCannotRunWith(t *testing.T) {
	own := netmap.GenerateWireGuardKey().Public()
	if _, err := dataplane.OverlayConfigFrom(overlaySection(), own, dataplane.MinOverlayMTU-1); !errors.Is(err, dataplane.ErrMTUTooSmall) {
		t.Fatalf("MTU below the minimum: %v", err)
	}
	for name, change := range map[string]func(*netmap.NodeSettings){
		"no IPv4":         func(n *netmap.NodeSettings) { n.IPv4 = netip.Addr{} },
		"IPv4 outside":    func(n *netmap.NodeSettings) { n.IPv4 = netip.MustParseAddr("100.65.0.1") },
		"no IPv4 network": func(n *netmap.NodeSettings) { n.IPv4Network = netip.Prefix{} },
		"IPv6 as IPv4":    func(n *netmap.NodeSettings) { n.IPv4, n.IPv4Network = n.IPv6, n.IPv6Network },
	} {
		s := overlaySection()
		change(&s.Node)
		if _, err := dataplane.OverlayConfigFrom(s, own, 1328); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestInboundFromStampsTheSpaceAndSkipsWhatItCannotUse(t *testing.T) {
	reg, err := transport.NewRegistry(udp.New(udp.Options{}), memory.NewNetwork(memory.Datagram))
	if err != nil {
		t.Fatal(err)
	}
	secret := bytes.Repeat([]byte{7}, udp.MinSecretSize)
	space := transport.SpaceID{9}
	s := netmap.Section{
		Node: netmap.NodeSettings{ID: nid(1)},
		Inbound: []netmap.InboundLink{
			{Peer: nid(2), Transport: "udp", Credential: secret},
			{Peer: nid(3), Transport: memory.Name, Credential: []byte("m")},
			{Peer: nid(4), Transport: "carrier-pigeon", Credential: secret},
			{Peer: nid(5), Transport: "udp", Credential: []byte("short")},
			{Peer: nid(6), Transport: "udp", Credential: secret, Shaping: []byte{0xff, 0xff}},
			{Peer: nid(1), Transport: "udp", Credential: secret},
		},
	}
	c := dataplane.InboundFrom(s, reg, space)
	if len(c.Links["udp"]) != 1 || len(c.Links[memory.Name]) != 1 || len(c.Skipped) != 4 {
		t.Fatalf("links %v, skipped %v", c.Links, c.Skipped)
	}
	if pl := c.Links["udp"][0]; pl.Peer != (transport.Identity{Space: space, Node: transport.NodeID(nid(2))}) || !bytes.Equal(pl.Verifier, secret) {
		t.Fatalf("udp link %+v", pl)
	}
}

// On a server with ingress off, the one inbound table keeps only other
// servers' links, and a device is no first hop or next hop there either.
func TestAcceptedInboundHonoursIngress(t *testing.T) {
	reg := udpRegistry(t)
	secret := func(b byte) []byte { return bytes.Repeat([]byte{b}, udp.MinSecretSize) }
	s := netmap.Section{
		Node: netmap.NodeSettings{ID: nid(1), Kind: netmap.NodeServer},
		Inbound: []netmap.InboundLink{
			{Peer: nid(2), PeerKind: netmap.NodeServer, Transport: "udp", Credential: secret(2)},
			{Peer: nid(3), PeerKind: netmap.NodeDevice, Transport: "udp", Credential: secret(3)},
			{Peer: nid(4), PeerKind: 9, Transport: "udp", Credential: secret(4)},
		},
		Routes: []netmap.Route{{Destination: nid(3), NextHops: []netmap.NodeID{nid(3)}}},
	}
	accepted := func() []transport.NodeID {
		var ids []transport.NodeID
		for _, l := range dataplane.AcceptedInbound(s, reg, transport.SpaceID{9}, 0).Links["udp"] {
			ids = append(ids, l.Peer.Node)
		}
		return ids
	}

	if got := accepted(); !slices.Equal(got, []transport.NodeID{transport.NodeID(nid(2))}) {
		t.Fatalf("ingress off accepts %v, want only the server", got)
	}
	in := dataplane.AcceptedInbound(s, reg, transport.SpaceID{9}, 0)
	if len(in.Skipped) != 2 || in.Skipped[0].Reason != dataplane.ReasonIngressOff || in.Skipped[1].Reason != dataplane.ReasonIngressOff {
		t.Fatalf("skipped %v", in.Skipped)
	}
	if pc := dataplane.PathConfigFrom(s, reg); len(pc.Table.Routes) != 0 {
		t.Fatalf("routes through a refused device: %+v", pc.Table.Routes)
	}

	s.Node.AllowIngress = true
	if got := accepted(); len(got) != 3 {
		t.Fatalf("ingress on accepts %v, want all three", got)
	}
	if pc := dataplane.PathConfigFrom(s, reg); len(pc.Table.Routes) != 1 {
		t.Fatalf("routes %+v, want the one to the device", pc.Table.Routes)
	}
}
