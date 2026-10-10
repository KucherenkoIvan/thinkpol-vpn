package netmap

import (
	"crypto/ed25519"
	"fmt"
	"net/netip"
	"testing"
)

// fixture is a space with servers and devices wired like an M0 overlay:
// every device links to every server, servers relay between devices.
type fixture struct {
	signing  ed25519.PrivateKey
	recovery ed25519.PrivateKey
	keys     []NodePrivateKey // keys[i] opens contents.Sections[i]
	contents Contents
}

var (
	testIPv4Net = netip.MustParsePrefix("100.100.0.0/16")
	testIPv6Net = netip.MustParsePrefix("fd12:3456:789a::/48")
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
		Version:     1,
		RecoveryKey: f.recovery.Public().(ed25519.PublicKey),
		Blobs:       []BlobRef{{SHA256: [32]byte{1, 2, 3}, Size: 4096}},
	}
	n := servers + devices
	ids := make([]NodeID, n)
	wg := make([]WireGuardKey, n)
	for i := range n {
		ids[i] = NewNodeID()
		wg[i] = WireGuardKey(GenerateNodeKey().Public()) // any 32 non-zero bytes
	}
	addrs := func(i int) (netip.Addr, netip.Addr) {
		v4 := testIPv4Net.Addr().As4()
		v4[2], v4[3] = byte((i+1)>>8), byte(i+1)
		v6 := testIPv6Net.Addr().As16()
		v6[14], v6[15] = byte((i+1)>>8), byte(i+1)
		return netip.AddrFrom4(v4), netip.AddrFrom16(v6)
	}
	cred := func(a, b int) []byte {
		return []byte(fmt.Sprintf("link-key-%d-%d-0123456789abcdef", min(a, b), max(a, b)))
	}
	isServer := func(i int) bool { return i < servers }

	for i := range n {
		v4, v6 := addrs(i)
		s := Section{Node: NodeSettings{
			ID: ids[i], IPv4: v4, IPv6: v6,
			IPv4Network: testIPv4Net, IPv6Network: testIPv6Net,
		}}
		if isServer(i) {
			s.Node.Kind = NodeServer
			s.Node.Listeners = []Listener{{Transport: "udp", Address: ":4500"}}
			for d := servers; d < n; d++ {
				s.Inbound = append(s.Inbound, InboundLink{Peer: ids[d], Transport: "udp", Credential: cred(i, d)})
				s.RelayTo = append(s.RelayTo, ids[d])
			}
		} else {
			s.Node.Kind = NodeDevice
			for srv := range servers {
				s.Links = append(s.Links, Link{Peer: ids[srv], Endpoints: []Endpoint{
					{Transport: "udp", Address: fmt.Sprintf("203.0.113.%d:4500", srv+1), Credential: cred(i, srv)},
				}})
			}
			for d := servers; d < n; d++ {
				if d == i || servers == 0 {
					continue
				}
				pv4, pv6 := addrs(d)
				p := Peer{ID: ids[d], WireGuardKey: wg[d], Addresses: []netip.Addr{pv4, pv6}}
				for srv := range servers {
					p.Paths = append(p.Paths, Path{Via: []NodeID{ids[srv]}})
				}
				s.Peers = append(s.Peers, p)
			}
		}
		key := GenerateNodeKey()
		f.keys = append(f.keys, key)
		f.contents.Sections = append(f.contents.Sections, Recipient{Key: key.Public(), Section: s})
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

func (f *fixture) verify(t testing.TB, env []byte) *Map {
	t.Helper()
	m, err := Verify(env, f.signingPublic())
	if err != nil {
		t.Fatal(err)
	}
	return m
}
