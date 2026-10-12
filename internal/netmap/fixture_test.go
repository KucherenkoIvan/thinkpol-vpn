package netmap

import (
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"slices"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport"
)

// Shaping as the controller encodes it: entries pad what they send to
// devices to buckets, devices pad at random.
var (
	bucketShaping = mustMarshal(transport.Shaping{Padding: transport.Buckets(128, 256, 512, 1024, 1452)})
	randomShaping = mustMarshal(transport.Shaping{Padding: transport.Padding{Mode: transport.PadRandom, Max: 64}})
)

func mustMarshal(s transport.Shaping) []byte {
	b, err := s.Marshal()
	if err != nil {
		panic(err)
	}
	return b
}

// fixture is a space wired the way maps will be:
//   - servers form a mesh: each dials every later server;
//   - with two or more servers the last one is an exit that devices can't
//     reach (egress on, ingress off) and the others are entries (ingress
//     on); one server is just an entry;
//   - every device dials every entry over udp and tls (two endpoints) and
//     has a direct path to it; other devices and the exit are reached with
//     the entries as candidate first hops;
//   - entries route to devices directly and to the exit, the first entry
//     through a hop group of the next two when there are four servers or
//     more;
//   - devices use a named GeoIP blob (and don't listen: no direct paths
//     between devices yet);
//   - with an exit, devices have routing rules sending all but local and
//     domestic destinations through a chain to it.
type fixture struct {
	signing  ed25519.PrivateKey
	recovery ed25519.PrivateKey
	keys     []NodePrivateKey // keys[i] opens contents.Recipients[i]
	contents Contents
}

var (
	testIPv4Net = netip.MustParsePrefix("100.100.0.0/16")
	testIPv6Net = netip.MustParsePrefix("fd12:3456:789a::/48")
	testGeoIP   = BlobRef{Kind: BlobGeoIP, SHA256: [32]byte{1, 2, 3}, Size: 4096}
	testGeoSite = BlobRef{Kind: BlobGeoSite, SHA256: [32]byte{4, 5, 6}, Size: 2048}
)

func newKeyPair(t testing.TB) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func newFixture(t testing.TB, servers, devices int) *fixture {
	t.Helper()
	f := &fixture{signing: newKeyPair(t), recovery: newKeyPair(t)}
	f.contents = Contents{
		SpaceID:     NewSpaceID(),
		KeyEpoch:    0,
		Version:     1,
		RecoveryKey: f.recovery.Public().(ed25519.PublicKey),
		Blobs:       []BlobRef{testGeoIP, testGeoSite},
	}
	n := servers + devices
	ids := make([]NodeID, n)
	wg := make([]WireGuardKey, n)
	for i := range n {
		ids[i] = NewNodeID()
		wg[i] = WireGuardKey(GenerateNodeKey().Public()) // any 32 non-zero bytes
	}
	addrs := func(i int) []netip.Addr {
		v4 := testIPv4Net.Addr().As4()
		v4[2], v4[3] = byte((i+1)>>8), byte(i+1)
		v6 := testIPv6Net.Addr().As16()
		v6[14], v6[15] = byte((i+1)>>8), byte(i+1)
		return []netip.Addr{netip.AddrFrom4(v4), netip.AddrFrom16(v6)}
	}
	cred := func(a, b int, transport string) []byte {
		return []byte(fmt.Sprintf("%s-link-key-%d-%d-0123456789abcdef", transport, min(a, b), max(a, b)))
	}
	exit := -1
	if servers >= 2 {
		exit = servers - 1
	}
	var entries []int
	for i := range servers {
		if i != exit {
			entries = append(entries, i)
		}
	}
	isDevice := func(i int) bool { return i >= servers }
	viaEntries := func() []Path {
		var p []Path
		for _, e := range entries {
			p = append(p, Path{FirstHop: ids[e]})
		}
		return p
	}

	sections := make([]Section, n)
	for i := range n {
		a := addrs(i)
		sections[i].Node = NodeSettings{
			ID: ids[i], IPv4: a[0], IPv6: a[1],
			IPv4Network: testIPv4Net, IPv6Network: testIPv6Net,
		}
	}
	peer := func(i int, paths []Path) Peer {
		return Peer{ID: ids[i], WireGuardKey: wg[i], Addresses: addrs(i), Paths: paths}
	}

	for i := range servers {
		s := &sections[i]
		s.Node.Kind = NodeServer
		s.Node.Listeners = []Listener{
			{Transport: "udp", Address: netip.MustParseAddrPort("0.0.0.0:4500")},
			{Transport: "tls", Address: netip.MustParseAddrPort("[::]:443"), Settings: []byte("camouflage=www.example.org")},
		}
		for j := i + 1; j < servers; j++ {
			s.Links = append(s.Links, Link{Peer: ids[j], Endpoints: []Endpoint{
				{Transport: "udp", Address: netip.MustParseAddrPort(fmt.Sprintf("198.51.100.%d:4500", j+1)), Credential: cred(i, j, "udp")},
			}})
			sections[j].Inbound = append(sections[j].Inbound, InboundLink{
				Peer: ids[i], PeerKind: NodeServer, Transport: "udp", Credential: cred(i, j, "udp"),
			})
		}
	}
	if exit >= 0 {
		sections[exit].Node.AllowEgress = true
	}
	for _, e := range entries {
		s := &sections[e]
		s.Node.AllowIngress = true
		for d := servers; d < n; d++ {
			s.Inbound = append(s.Inbound,
				InboundLink{Peer: ids[d], PeerKind: NodeDevice, Transport: "udp", Credential: cred(e, d, "udp")},
				InboundLink{Peer: ids[d], PeerKind: NodeDevice, Transport: "tls", Credential: cred(e, d, "tls"), Settings: []byte("sni=www.example.org"), Shaping: bucketShaping},
			)
			s.Peers = append(s.Peers, peer(d, []Path{{FirstHop: ids[d]}}))
			s.Routes = append(s.Routes, Route{Destination: ids[d], NextHops: []NodeID{ids[d]}})
		}
		if exit >= 0 {
			hops := []NodeID{ids[exit]}
			if e == 0 && servers >= 4 {
				hops = []NodeID{ids[1], ids[2]} // a hop group in the middle
			}
			s.Routes = append(s.Routes, Route{Destination: ids[exit], NextHops: hops})
		}
	}
	if exit >= 0 {
		for d := servers; d < n; d++ {
			sections[exit].Peers = append(sections[exit].Peers, peer(d, viaEntries()))
		}
	}
	for d := servers; d < n; d++ {
		s := &sections[d]
		s.Node.Kind = NodeDevice
		s.Blobs = []BlobRef{{Kind: BlobGeoIP, SHA256: testGeoIP.SHA256, Size: testGeoIP.Size, Name: "ru"}}
		for _, e := range entries {
			s.Links = append(s.Links, Link{Peer: ids[e], Endpoints: []Endpoint{
				{Transport: "udp", Address: netip.MustParseAddrPort(fmt.Sprintf("203.0.113.%d:4500", e+1)), Credential: cred(e, d, "udp")},
				{Transport: "tls", Address: netip.MustParseAddrPort(fmt.Sprintf("[2001:db8::%x]:443", e+1)), Credential: cred(e, d, "tls"), Settings: []byte("pin=sha256:abcd"), Shaping: randomShaping},
			}})
			s.Peers = append(s.Peers, peer(e, []Path{{FirstHop: ids[e]}}))
		}
		if len(entries) == 0 {
			continue
		}
		if exit >= 0 {
			s.Peers = append(s.Peers, peer(exit, viaEntries()))
			s.Chains = []Chain{{Name: "nl", Exit: ids[exit]}}
			s.Rules = []Rule{
				{Match{Kind: MatchLocal}, Direct},
				{Match{Kind: MatchDomainSuffix, Value: "example.ru"}, Direct},
				{Match{Kind: MatchGeoIP, Value: "ru"}, Direct},
				{Match{Kind: MatchCIDR, Prefix: netip.MustParsePrefix("2001:db8::/32")}, Block},
				{Match{Kind: MatchDefault}, ToChain("nl")},
			}
			s.Presets = RulePresets{Domestic: "ru", Chain: "nl"}
		}
		for o := servers; o < n; o++ {
			if o != d && isDevice(o) {
				s.Peers = append(s.Peers, peer(o, viaEntries()))
			}
		}
		// Overlay names: devices' sections only.
		s.SpaceName, s.Node.Name = "home", fmt.Sprintf("node-%d", d)
		for i := range s.Peers {
			s.Peers[i].Name = fmt.Sprintf("node-%d", slices.Index(ids, s.Peers[i].ID))
		}
	}

	for i := range n {
		key := GenerateNodeKey()
		f.keys = append(f.keys, key)
		f.contents.Recipients = append(f.contents.Recipients, Recipient{Key: key.Public(), Section: sections[i]})
	}
	return f
}

func (f *fixture) build(t testing.TB) []byte {
	t.Helper()
	env, err := Build(f.signing, f.contents)
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (f *fixture) signingPublic() ed25519.PublicKey {
	return f.signing.Public().(ed25519.PublicKey)
}

func (f *fixture) trust() Trust {
	return Trust{SpaceID: f.contents.SpaceID, SigningKey: f.signingPublic(), RecoveryKey: f.contents.RecoveryKey}
}

func (f *fixture) verify(t testing.TB, env []byte) *Map {
	t.Helper()
	m, err := Verify(env, f.trust())
	if err != nil {
		t.Fatal(err)
	}
	return m
}
