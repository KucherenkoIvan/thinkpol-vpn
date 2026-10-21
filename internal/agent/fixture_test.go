package agent

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/transport/memory"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
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
	// blobs are the header's blobs; b's section names deviceBlobs.
	blobs, deviceBlobs []netmap.BlobRef
	// deviceRules are b's routing rules.
	deviceRules []netmap.Rule
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
	b.Blobs = s.deviceBlobs
	b.Rules = s.deviceRules
	return a, b
}

// build signs a map of the space at version.
func (s *testSpace) build(t *testing.T, version uint64) []byte {
	t.Helper()
	return s.buildEditing(t, version, s.a, func(*netmap.Section) {})
}

// buildEditing signs a map at version whose section for who (a's or b's)
// is changed by edit.
func (s *testSpace) buildEditing(t *testing.T, version uint64, who NodeKeys, edit func(*netmap.Section)) []byte {
	t.Helper()
	if who != s.a && who != s.b {
		t.Fatalf("the edited node %v is neither of the space's two", who.ID)
	}
	a, b := s.sections()
	edited := &a
	if who == s.b {
		edited = &b
	}
	edit(edited)
	env, err := netmap.Build(s.signing, netmap.Contents{
		SpaceID: s.id, Version: version, RecoveryKey: s.recovery, Blobs: s.blobs,
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
		SpaceID: s.id, Version: version, RecoveryKey: s.recovery, Blobs: s.blobs,
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

// withList gives the space a GeoIP list named name: in the header, and
// named in device b's section. It returns the list's bytes and b's
// reference.
func (s *testSpace) withList(t *testing.T, name string, prefixes ...string) ([]byte, netmap.BlobRef) {
	t.Helper()
	var lb lists.Builder
	for _, p := range prefixes {
		if err := lb.AddPrefix(netip.MustParsePrefix(p)); err != nil {
			t.Fatal(err)
		}
	}
	set, _ := lb.Build()
	data := set.Blob()
	ref := netmap.BlobRef{Kind: netmap.BlobGeoIP, SHA256: sha256.Sum256(data), Size: uint64(len(data))}
	s.blobs = append(s.blobs, ref)
	ref.Name = name
	s.deviceBlobs = append(s.deviceBlobs, ref)
	return data, ref
}

// heardEvents records a node's events.
type heardEvents struct {
	mu  sync.Mutex
	evs []Event
	// asserted is the last list are matched: no other event may come.
	asserted []Event
	checked  bool
}

// newHeardEvents records events; once t's later cleanups ran (the node
// stopped), the events heard must be the last list are matched.
func newHeardEvents(t *testing.T) *heardEvents {
	h := &heardEvents{}
	t.Cleanup(func() {
		h.mu.Lock()
		defer h.mu.Unlock()
		if h.checked && !slices.Equal(h.evs, h.asserted) {
			t.Errorf("events %v, want %v and nothing more", h.evs, h.asserted)
		}
	})
	return h
}

func (h *heardEvents) add(ev Event) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.evs = append(h.evs, ev)
}

func (h *heardEvents) get() []Event {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.evs)
}

// are waits until the events heard are want.
func (h *heardEvents) are(t *testing.T, want ...Event) {
	t.Helper()
	h.mu.Lock()
	h.asserted, h.checked = want, true
	h.mu.Unlock()
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(10 * time.Millisecond) {
		got := h.get()
		if slices.Equal(got, want) {
			return
		}
		if len(got) >= len(want) || time.Now().After(deadline) {
			t.Fatalf("events %v, want %v", got, want)
		}
	}
}

// buildEditing edits the section of the node it names and no other's:
// an edit of b changes b's section, a's stays as it was.
func TestBuildEditingEditsTheNamedNode(t *testing.T) {
	s := newTestSpace(t)
	m, err := netmap.Verify(s.buildEditing(t, 2, s.b, func(sec *netmap.Section) { sec.Node.IPv4 = netip.MustParseAddr("100.64.0.9") }), s.trust())
	if err != nil {
		t.Fatal(err)
	}
	aSec, err := openSection(m, s.a)
	if err != nil {
		t.Fatal(err)
	}
	bSec, err := openSection(m, s.b)
	if err != nil {
		t.Fatal(err)
	}
	if bSec.Node.IPv4 != netip.MustParseAddr("100.64.0.9") {
		t.Error("the edit didn't reach b's section")
	}
	if aSec.Node.IPv4 == netip.MustParseAddr("100.64.0.9") {
		t.Error("the edit reached a's section")
	}
}
