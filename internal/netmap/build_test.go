package netmap

import (
	"bytes"
	"errors"
	"net/netip"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/shaping"
)

// TestBuildRejectsInvalidContents covers Build's policy and consistency
// checks; readers don't repeat them (TestOpenChecksOnlyWellFormedness).
func TestBuildRejectsInvalidContents(t *testing.T) {
	// Recipients: 0 entry, 1 exit, 2 and 3 devices (see newFixture).
	f := newFixture(t, 2, 2)
	type mutation func(c *Contents)
	section := func(i int, m func(s *Section)) mutation {
		return func(c *Contents) {
			recipients := append([]Recipient(nil), c.Recipients...)
			s := recipients[i].Section
			s.Node.Listeners = append([]Listener(nil), s.Node.Listeners...)
			s.Peers = append([]Peer(nil), s.Peers...)
			s.Links = append([]Link(nil), s.Links...)
			s.Inbound = append([]InboundLink(nil), s.Inbound...)
			s.Routes = append([]Route(nil), s.Routes...)
			s.Blobs = append([]BlobRef(nil), s.Blobs...)
			s.Rules = append([]Rule(nil), s.Rules...)
			s.Chains = append([]Chain(nil), s.Chains...)
			m(&s)
			recipients[i].Section = s
			c.Recipients = recipients
		}
	}
	entry := func(m func(s *Section)) mutation { return section(0, m) }
	device := func(m func(s *Section)) mutation { return section(2, m) }
	entryID := f.contents.Recipients[0].Section.Node.ID
	exitID := f.contents.Recipients[1].Section.Node.ID
	lowOrder := mustKey(t, "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")

	tests := []struct {
		name   string
		mutate mutation
	}{
		// header
		{"zero space id", func(c *Contents) { c.SpaceID = SpaceID{} }},
		{"zero version", func(c *Contents) { c.Version = 0 }},
		{"version above 2^53", func(c *Contents) { c.Version = MaxVersion + 1 }},
		{"no recovery key", func(c *Contents) { c.RecoveryKey = nil }},
		{"recovery key is the signing key", func(c *Contents) { c.RecoveryKey = f.signingPublic() }},
		{"zero blob hash", func(c *Contents) { c.Blobs = []BlobRef{{Kind: BlobGeoIP, Size: 1}} }},
		{"blob of size 0", func(c *Contents) { c.Blobs = []BlobRef{{Kind: BlobGeoIP, SHA256: [32]byte{9}}} }},
		{"blob of unknown kind", func(c *Contents) { c.Blobs = []BlobRef{{Kind: 9, SHA256: [32]byte{9}, Size: 1}} }},
		{"blob named in the header", func(c *Contents) { c.Blobs = []BlobRef{{Kind: BlobGeoIP, SHA256: [32]byte{9}, Size: 1, Name: "ru"}} }},
		{"repeated blob", func(c *Contents) { c.Blobs = []BlobRef{testGeoIP, testGeoIP} }},
		// recipients
		{"zero recipient key", func(c *Contents) {
			c.Recipients = append([]Recipient(nil), c.Recipients...)
			c.Recipients[0].Key = NodePublicKey{}
		}},
		{"low-order recipient key", func(c *Contents) {
			c.Recipients = append([]Recipient(nil), c.Recipients...)
			c.Recipients[0].Key = lowOrder
		}},
		{"repeated recipient key", func(c *Contents) {
			c.Recipients = append([]Recipient(nil), c.Recipients...)
			c.Recipients[1].Key = c.Recipients[0].Key
		}},
		{"two sections for one node", func(c *Contents) {
			c.Recipients = append([]Recipient(nil), c.Recipients...)
			c.Recipients[1].Section = c.Recipients[0].Section
		}},
		{"too many sections", func(c *Contents) { c.Recipients = make([]Recipient, maxSections+1) }},
		// node settings
		{"zero node id", entry(func(s *Section) { s.Node.ID = NodeID{} })},
		{"unknown kind", entry(func(s *Section) { s.Node.Kind = 7 })},
		{"IPv4 network outside CGNAT", entry(func(s *Section) { s.Node.IPv4Network = netip.MustParsePrefix("10.0.0.0/8") })},
		{"IPv4 network wider than CGNAT", entry(func(s *Section) { s.Node.IPv4Network = netip.MustParsePrefix("100.0.0.0/8") })},
		{"IPv4 network not masked", entry(func(s *Section) { s.Node.IPv4Network = netip.MustParsePrefix("100.100.0.1/16") })},
		{"IPv6 network not ULA", entry(func(s *Section) { s.Node.IPv6Network = netip.MustParsePrefix("2001:db8::/48") })},
		{"IPv6 network in fc00::/8", entry(func(s *Section) { s.Node.IPv6Network = netip.MustParsePrefix("fc12:3456:789a::/48") })},
		{"IPv6 network not a /48", entry(func(s *Section) { s.Node.IPv6Network = netip.MustParsePrefix("fd12:3456::/32") })},
		{"IPv6 network is IPv4", entry(func(s *Section) { s.Node.IPv6Network = netip.MustParsePrefix("100.100.0.0/16") })},
		{"no IPv6 network", entry(func(s *Section) { s.Node.IPv6Network = netip.Prefix{} })},
		{"address outside network", entry(func(s *Section) { s.Node.IPv4 = netip.MustParseAddr("100.101.0.1") })},
		{"no IPv6 address", entry(func(s *Section) { s.Node.IPv6 = netip.Addr{} })},
		// listeners
		{"bad transport name", entry(func(s *Section) { s.Node.Listeners[0].Transport = "UDP" })},
		{"transport name starts with a digit", entry(func(s *Section) { s.Node.Listeners[0].Transport = "4udp" })},
		{"long transport name", entry(func(s *Section) { s.Node.Listeners[0].Transport = string(bytes.Repeat([]byte("a"), 33)) })},
		{"listener without address", entry(func(s *Section) { s.Node.Listeners[0].Address = netip.AddrPort{} })},
		{"listener port zero", entry(func(s *Section) { s.Node.Listeners[0].Address = netip.MustParseAddrPort("0.0.0.0:0") })},
		{"listener with a zone", entry(func(s *Section) { s.Node.Listeners[0].Address = netip.MustParseAddrPort("[fe80::1%eth0]:4500") })},
		{"listener on IPv4-mapped IPv6", entry(func(s *Section) { s.Node.Listeners[0].Address = netip.MustParseAddrPort("[::ffff:192.0.2.1]:4500") })},
		{"listener repeated", entry(func(s *Section) { s.Node.Listeners = append(s.Node.Listeners, s.Node.Listeners[0]) })},
		{"listener settings too long", entry(func(s *Section) { s.Node.Listeners[0].Settings = make([]byte, maxSettings+1) })},
		// inbound links
		{"inbound from self", entry(func(s *Section) { s.Inbound[0].Peer = entryID })},
		{"inbound repeated", entry(func(s *Section) { s.Inbound = append(s.Inbound, s.Inbound[0]) })},
		{"inbound without credential", entry(func(s *Section) { s.Inbound[0].Credential = nil })},
		{"inbound credential too long", entry(func(s *Section) { s.Inbound[0].Credential = make([]byte, maxCredential+1) })},
		{"inbound peer kind unknown", entry(func(s *Section) { s.Inbound[0].PeerKind = 0 })},
		{"inbound settings too long", entry(func(s *Section) { s.Inbound[0].Settings = make([]byte, maxSettings+1) })},
		{"inbound shaping too long", entry(func(s *Section) { s.Inbound[0].Shaping = make([]byte, maxSettings+1) })},
		{"inbound shaping undecodable", entry(func(s *Section) { s.Inbound[0].Shaping = []byte("pad=buckets") })},
		{"inbound shaping with an unknown field", entry(func(s *Section) { s.Inbound[0].Shaping = append(bytes.Clone(bucketShaping), 0xf8, 0x06, 0x01) })},
		{"inbound credential shared", entry(func(s *Section) { s.Inbound[3].Credential = s.Inbound[1].Credential })},
		// routes
		{"route to self", entry(func(s *Section) { s.Routes = append(s.Routes, Route{Destination: entryID, NextHops: []NodeID{exitID}}) })},
		{"route to zero", entry(func(s *Section) { s.Routes = append(s.Routes, Route{NextHops: []NodeID{exitID}}) })},
		{"route repeated", entry(func(s *Section) { s.Routes = append(s.Routes, s.Routes[0]) })},
		{"route without next hops", entry(func(s *Section) { s.Routes[0].NextHops = nil })},
		{"next hop is self", entry(func(s *Section) { s.Routes[0].NextHops = []NodeID{entryID} })},
		{"next hop repeated", entry(func(s *Section) { s.Routes[0].NextHops = []NodeID{exitID, exitID} })},
		{"next hop not adjacent", entry(func(s *Section) { s.Routes[0].NextHops = []NodeID{{7, 7, 7}} })},
		// links
		{"link repeated", device(func(s *Section) { s.Links = append(s.Links, s.Links[0]) })},
		{"link without endpoints", device(func(s *Section) { s.Links[0] = Link{Peer: s.Links[0].Peer} })},
		{"endpoint without address", device(func(s *Section) {
			s.Links[0] = Link{Peer: s.Links[0].Peer, Endpoints: []Endpoint{{Transport: "udp", Credential: []byte{1}}}}
		})},
		{"endpoint to an unspecified address", device(func(s *Section) {
			s.Links[0] = Link{Peer: s.Links[0].Peer, Endpoints: []Endpoint{{Transport: "udp", Address: netip.MustParseAddrPort("0.0.0.0:4500"), Credential: []byte{1}}}}
		})},
		{"endpoint port zero", device(func(s *Section) {
			s.Links[0] = Link{Peer: s.Links[0].Peer, Endpoints: []Endpoint{{Transport: "udp", Address: netip.MustParseAddrPort("192.0.2.1:0"), Credential: []byte{1}}}}
		})},
		{"endpoint repeated", device(func(s *Section) {
			s.Links[0] = Link{Peer: s.Links[0].Peer, Endpoints: append(s.Links[0].Endpoints, s.Links[0].Endpoints[0])}
		})},
		{"endpoint settings too long", device(func(s *Section) {
			e := s.Links[0].Endpoints[0]
			e.Settings = make([]byte, maxSettings+1)
			s.Links[0] = Link{Peer: s.Links[0].Peer, Endpoints: []Endpoint{e}}
		})},
		{"endpoint shaping too long", device(func(s *Section) {
			e := s.Links[0].Endpoints[0]
			e.Shaping = make([]byte, maxSettings+1)
			s.Links[0] = Link{Peer: s.Links[0].Peer, Endpoints: []Endpoint{e}}
		})},
		{"endpoint shaping invalid", device(func(s *Section) {
			e := s.Links[0].Endpoints[0]
			e.Shaping = []byte{0x0a, 0x04, 0x08, 0x80, 0x02, 0x08} // buckets: 256, then a truncated size
			s.Links[0] = Link{Peer: s.Links[0].Peer, Endpoints: []Endpoint{e}}
		})},
		// peers
		{"peer is self", device(func(s *Section) { s.Peers[0].ID = s.Node.ID })},
		{"peer repeated", device(func(s *Section) { s.Peers = append(s.Peers, s.Peers[0]) })},
		{"peer without WireGuard key", device(func(s *Section) { s.Peers[0].WireGuardKey = WireGuardKey{} })},
		{"peer without addresses", device(func(s *Section) { s.Peers[0].Addresses = nil })},
		{"peer address outside overlay", device(func(s *Section) { s.Peers[0].Addresses = []netip.Addr{netip.MustParseAddr("192.0.2.1")} })},
		{"peer address repeated", device(func(s *Section) {
			s.Peers[0].Addresses = []netip.Addr{s.Peers[0].Addresses[0], s.Peers[0].Addresses[0]}
		})},
		{"peer address taken by another peer", device(func(s *Section) { s.Peers[1].Addresses = s.Peers[0].Addresses })},
		{"peer address is the node's own", device(func(s *Section) { s.Peers[0].Addresses = []netip.Addr{s.Node.IPv4} })},
		{"peer without paths", device(func(s *Section) { s.Peers[0].Paths = nil })},
		{"path through self", device(func(s *Section) { s.Peers[0].Paths = []Path{{FirstHop: s.Node.ID}} })},
		{"path repeated", device(func(s *Section) { s.Peers[0].Paths = []Path{s.Peers[0].Paths[0], s.Peers[0].Paths[0]} })},
		{"first hop not adjacent", device(func(s *Section) { s.Peers[0].Paths = []Path{{FirstHop: exitID}} })},
		// blobs
		{"blob not in the header", device(func(s *Section) { s.Blobs = []BlobRef{{Kind: BlobGeoIP, SHA256: [32]byte{9}, Size: 1, Name: "x"}} })},
		{"blob kind differs from the header", device(func(s *Section) {
			s.Blobs = []BlobRef{{Kind: BlobGeoSite, SHA256: testGeoIP.SHA256, Size: testGeoIP.Size}}
		})},
		{"blob repeated", device(func(s *Section) { s.Blobs = append(s.Blobs, s.Blobs[0]) })},
		// rules
		{"rule with unknown matcher", device(func(s *Section) { s.Rules[0].Match.Kind = 9 })},
		{"rule with unknown action", device(func(s *Section) { s.Rules[0].Action.Kind = 9 })},
		{"default with an argument", device(func(s *Section) { s.Rules[4].Match.Value = "x" })},
		{"cidr with host bits", device(func(s *Section) { s.Rules[3].Match.Prefix = netip.MustParsePrefix("2001:db8::1/32") })},
		{"cidr without prefix", device(func(s *Section) { s.Rules[3].Match.Prefix = netip.Prefix{} })},
		{"cidr over IPv4-mapped IPv6", device(func(s *Section) { s.Rules[3].Match.Prefix = netip.MustParsePrefix("::/0") })},
		{"geoip list without a blob", device(func(s *Section) { s.Rules[2].Match.Value = "de" })},
		{"geoip list name invalid", device(func(s *Section) { s.Rules[2].Match.Value = "RU" })},
		{"geosite list without a blob", device(func(s *Section) { s.Rules[2].Match = Match{Kind: MatchGeoSite, Value: "ru"} })},
		{"domain invalid", device(func(s *Section) { s.Rules[1].Match.Value = "Example.RU" })},
		{"domain with an empty label", device(func(s *Section) { s.Rules[1].Match.Value = "example..ru" })},
		{"no default rule last", device(func(s *Section) { s.Rules = s.Rules[:4] })},
		{"chain unknown", device(func(s *Section) { s.Rules[4].Action = ToChain("de") })},
		{"direct naming a chain", device(func(s *Section) { s.Rules[0].Action.Chain = "nl" })},
		{"chain name invalid", device(func(s *Section) { s.Chains[0].Name = "NL" })},
		{"chain repeated", device(func(s *Section) { s.Chains = append(s.Chains, s.Chains[0]) })},
		{"chain exit not a peer", device(func(s *Section) { s.Chains[0].Exit = NodeID{7, 7, 7} })},
		{"chain exit is the node", device(func(s *Section) { s.Chains[0].Exit = s.Node.ID })},
		{"two chains to one exit", device(func(s *Section) { s.Chains = append(s.Chains, Chain{Name: "nl2", Exit: exitID}) })},
		{"preset domestic without a blob", device(func(s *Section) { s.Presets.Domestic = "de" })},
		{"preset chain unknown", device(func(s *Section) { s.Presets.Chain = "de" })},
		{"two geoip blobs with one name", device(func(s *Section) {
			s.Blobs = append(s.Blobs, BlobRef{Kind: BlobGeoIP, SHA256: testGeoSite.SHA256, Size: testGeoSite.Size, Name: "ru"})
		})},
		// size
		{"section too large", device(func(s *Section) {
			for i := range 1100 {
				id := NodeID{byte(i), byte(i >> 8), 1}
				s.Links = append(s.Links, Link{Peer: id, Endpoints: []Endpoint{{Transport: "udp", Address: netip.MustParseAddrPort("192.0.2.1:1"), Credential: make([]byte, maxCredential)}}})
			}
		})},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := f.contents
			tt.mutate(&c)
			if _, err := Build(f.signing, c); !errors.Is(err, ErrInvalidContents) {
				t.Errorf("err = %v, want ErrInvalidContents", err)
			}
		})
	}
	if _, err := Build(f.signing[:10], f.contents); !errors.Is(err, ErrInvalidContents) {
		t.Errorf("short signing key: err = %v, want ErrInvalidContents", err)
	}
	if _, err := Build(f.signing, f.contents); err != nil {
		t.Fatalf("control: the unmodified contents fail: %v", err)
	}
}

func mustKey(t testing.TB, s string) NodePublicKey {
	t.Helper()
	k, err := parseHex[NodePublicKey]("key", s)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// The builder applies the same shaping rules as the transport port.
func TestCheckSettingsDecodesShaping(t *testing.T) {
	for _, b := range [][]byte{nil, bucketShaping, randomShaping} {
		if err := checkSettings(nil, b); err != nil {
			t.Errorf("real shaping refused: %v", err)
		}
	}
	for name, tc := range map[string]struct {
		b    []byte
		want error
	}{
		"garbage":       {[]byte("pad=buckets"), shaping.ErrInvalid},
		"truncated":     {[]byte{0x0a, 0x04, 0x08, 0x80, 0x02, 0x08}, shaping.ErrInvalid},
		"descending":    {[]byte{0x0a, 0x05, 0x08, 0x80, 0x02, 0x08, 0x10}, shaping.ErrInvalid},
		"unknown field": {append(bytes.Clone(bucketShaping), 0xf8, 0x06, 0x01), shaping.ErrUnsupported},
	} {
		if err := checkSettings(nil, tc.b); !errors.Is(err, tc.want) {
			t.Errorf("%s: %v, want %v", name, err, tc.want)
		}
	}
}
