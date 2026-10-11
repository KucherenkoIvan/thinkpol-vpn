package agent

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// testSpace is a two-node space: server a (ingress on) listens, device b
// dials it, and each is the other's WireGuard peer.
type testSpace struct {
	signing  ed25519.PrivateKey
	recovery ed25519.PublicKey
	id       netmap.SpaceID
	a, b     NodeKeys
	// listen is a's listener address on the memory network.
	listen netip.AddrPort
	secret []byte
}

var (
	testV4 = netip.MustParsePrefix("100.64.0.0/10")
	testV6 = netip.MustParsePrefix("fd00:1:2::/48")
)

func newTestSpace(t *testing.T) *testSpace {
	t.Helper()
	_, signing, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	recovery, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	node := func(n byte) NodeKeys {
		return NodeKeys{ID: netmap.NodeID{0, 0, 0, 0, 0, 0, 0, n}, Map: netmap.GenerateNodeKey(), WireGuard: netmap.GenerateWireGuardKey()}
	}
	return &testSpace{
		signing: signing, recovery: recovery, id: netmap.NewSpaceID(),
		a: node(1), b: node(2),
		listen: netip.MustParseAddrPort("192.0.2.1:4500"),
		secret: []byte("a link secret of the test space"),
	}
}

func (s *testSpace) trust() netmap.Trust {
	return netmap.Trust{SpaceID: s.id, SigningKey: s.signing.Public().(ed25519.PublicKey), RecoveryKey: s.recovery}
}

func overlay(n byte) (netip.Addr, netip.Addr) {
	return netip.AddrFrom4([4]byte{100, 64, 0, n}), netip.MustParseAddr(fmt.Sprintf("fd00:1:2::%d", n))
}

// sections are a's and b's sections, for a listening on s.listen.
func (s *testSpace) sections() (a, b netmap.Section) {
	a4, a6 := overlay(1)
	b4, b6 := overlay(2)
	a.Node = netmap.NodeSettings{ID: s.a.ID, Kind: netmap.NodeServer, IPv4: a4, IPv6: a6, IPv4Network: testV4, IPv6Network: testV6,
		Listeners: []netmap.Listener{{Transport: memory.Name, Address: s.listen}}, AllowIngress: true}
	b.Node = netmap.NodeSettings{ID: s.b.ID, Kind: netmap.NodeDevice, IPv4: b4, IPv6: b6, IPv4Network: testV4, IPv6Network: testV6}
	a.Inbound = []netmap.InboundLink{{Peer: s.b.ID, PeerKind: netmap.NodeDevice, Transport: memory.Name, Credential: s.secret}}
	b.Links = []netmap.Link{{Peer: s.a.ID, Endpoints: []netmap.Endpoint{{Transport: memory.Name, Address: s.listen, Credential: s.secret}}}}
	a.Peers = []netmap.Peer{{ID: s.b.ID, WireGuardKey: s.b.WireGuard.Public(), Addresses: []netip.Addr{b4, b6}, Paths: []netmap.Path{{FirstHop: s.b.ID}}}}
	b.Peers = []netmap.Peer{{ID: s.a.ID, WireGuardKey: s.a.WireGuard.Public(), Addresses: []netip.Addr{a4, a6}, Paths: []netmap.Path{{FirstHop: s.a.ID}}}}
	return a, b
}

// build signs a map of the space at version.
func (s *testSpace) build(t *testing.T, version uint64) []byte {
	t.Helper()
	a, b := s.sections()
	env, err := netmap.Build(s.signing, netmap.Contents{
		SpaceID: s.id, Version: version, RecoveryKey: s.recovery,
		Recipients: []netmap.Recipient{{Key: s.a.Map.Public(), Section: a}, {Key: s.b.Map.Public(), Section: b}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

// buildWithout signs a map at version from which gone was removed: the
// other node alone, without its links to gone.
func (s *testSpace) buildWithout(t *testing.T, version uint64, gone NodeKeys) []byte {
	t.Helper()
	a, b := s.sections()
	stay, key := a, s.a.Map
	if gone == s.a {
		stay, key = b, s.b.Map
	}
	stay.Peers, stay.Links, stay.Inbound = nil, nil, nil
	env, err := netmap.Build(s.signing, netmap.Contents{
		SpaceID: s.id, Version: version, RecoveryKey: s.recovery,
		Recipients: []netmap.Recipient{{Key: key.Public(), Section: stay}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return env
}

func (s *testSpace) verified(t *testing.T, version uint64) *netmap.Map {
	t.Helper()
	m, err := netmap.Verify(s.build(t, version), s.trust())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// nodeKeyFile is a node.key as `thinkpol dev keygen node` writes it.
func nodeKeyFile(k NodeKeys) string {
	return fmt.Sprintf("# Keys of node x: private, only x gets this file\nnode-id: %q\nmap-key: %q\nwireguard-key: %q\n",
		k.ID.String(), hex.EncodeToString(k.Map[:]), hex.EncodeToString(k.WireGuard[:]))
}

// trustFile is a space.pub as `thinkpol dev keygen space` writes it.
func trustFile(tr netmap.Trust) string {
	return fmt.Sprintf("# Space public keys: every node verifies its maps with them\nspace-id: %q\nsigning-key: %q\nrecovery-key: %q\n",
		tr.SpaceID.String(), hex.EncodeToString(tr.SigningKey), hex.EncodeToString(tr.RecoveryKey))
}

// stateDir lays out node k's state directory with a map at version.
func (s *testSpace) stateDir(t *testing.T, k NodeKeys, version uint64) string {
	t.Helper()
	dir := filepath.Join(tempDir(t), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, NodeKeyFile), []byte(nodeKeyFile(k)), 0o600)
	writeFile(t, filepath.Join(dir, TrustFile), []byte(trustFile(s.trust())), 0o644)
	writeFile(t, filepath.Join(dir, MapFileName), s.build(t, version), 0o644)
	return dir
}

// writeFile writes with exactly perm, whatever the umask.
func writeFile(t *testing.T, path string, data []byte, perm os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, data, perm); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
}

// tempDir is a test's temporary directory by its real path: the node's
// files are refused behind a symlink, and macOS's temporary directories
// are under one (/var).
func tempDir(t *testing.T) string {
	t.Helper()
	d, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return d
}
