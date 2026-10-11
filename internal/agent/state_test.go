package agent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

func TestLoadStateOpensTheNodesSection(t *testing.T) {
	s := newTestSpace(t)
	dir := s.stateDir(t, s.b, 7)
	st, err := LoadState(dir, filepath.Join(dir, MapFile))
	if err != nil {
		t.Fatal(err)
	}
	if st.Keys != s.b || st.Section.Node.ID != s.b.ID || st.Map.Header().Version != 7 || st.Trust.SpaceID != s.id {
		t.Fatalf("state: keys %v, section of %v, version %d, space %v", st.Keys, st.Section.Node.ID, st.Map.Header().Version, st.Trust.SpaceID)
	}
	if len(st.Unexpected) != 0 {
		t.Fatalf("unexpected entries %v", st.Unexpected)
	}
}

func TestLoadStateReportsUnexpectedEntries(t *testing.T) {
	s := newTestSpace(t)
	dir := s.stateDir(t, s.b, 1)
	writeFile(t, filepath.Join(dir, "notes.txt"), []byte("x"), 0o600)
	st, err := LoadState(dir, filepath.Join(dir, MapFile))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(st.Unexpected, []string{"notes.txt"}) {
		t.Fatalf("unexpected %v", st.Unexpected)
	}
}

func TestLoadStateRefuses(t *testing.T) {
	other := newTestSpace(t)
	for _, tc := range []struct {
		name   string
		unix   bool // a mode check, skipped on Windows
		mutate func(t *testing.T, s *testSpace, dir string)
		want   string
	}{
		{"no key file", false, func(t *testing.T, _ *testSpace, dir string) { remove(t, dir, NodeKeyFile) }, "node.key"},
		{"no trust", false, func(t *testing.T, _ *testSpace, dir string) { remove(t, dir, TrustFile) }, "space.pub"},
		{"no map", false, func(t *testing.T, _ *testSpace, dir string) { remove(t, dir, MapFile) }, "map.bin"},
		{"a key file others can read", true, func(t *testing.T, _ *testSpace, dir string) {
			chmod(t, filepath.Join(dir, NodeKeyFile), 0o640)
		}, "chmod 600"},
		{"a state directory others can write", true, func(t *testing.T, _ *testSpace, dir string) { chmod(t, dir, 0o770) }, "chmod go-w"},
		{"a trust file others can write", true, func(t *testing.T, _ *testSpace, dir string) {
			chmod(t, filepath.Join(dir, TrustFile), 0o666)
		}, "chmod go-w"},
		{"the space's signing key", false, func(t *testing.T, _ *testSpace, dir string) {
			writeFile(t, filepath.Join(dir, "space.key"), []byte("x"), 0o600)
		}, "no place on a node"},
		{"the space's recovery key", false, func(t *testing.T, _ *testSpace, dir string) {
			writeFile(t, filepath.Join(dir, "recovery.key"), []byte("x"), 0o600)
		}, "no place on a node"},
		{"a map signed by another key", false, func(t *testing.T, _ *testSpace, dir string) {
			writeFile(t, filepath.Join(dir, TrustFile), []byte(trustFile(netmap.Trust{
				SpaceID: other.id, SigningKey: other.signing.Public().(ed25519.PublicKey), RecoveryKey: other.recovery,
			})), 0o644)
		}, "not a valid map"},
		{"a tampered map", false, func(t *testing.T, s *testSpace, dir string) {
			env := s.build(t, 1)
			env[len(env)-1] ^= 1
			writeFile(t, filepath.Join(dir, MapFile), env, 0o644)
		}, "not a valid map"},
		{"a map without the node", false, func(t *testing.T, _ *testSpace, dir string) {
			writeFile(t, filepath.Join(dir, NodeKeyFile), []byte(nodeKeyFile(NodeKeys{
				ID: netmap.NodeID{9}, Map: netmap.GenerateNodeKey(), WireGuard: netmap.GenerateWireGuardKey(),
			})), 0o600)
		}, "no section for this node's key"},
		{"another node's id", false, func(t *testing.T, s *testSpace, dir string) {
			k := s.b
			k.ID = s.a.ID
			writeFile(t, filepath.Join(dir, NodeKeyFile), []byte(nodeKeyFile(k)), 0o600)
		}, "the key file says"},
		{"a map too large", false, func(t *testing.T, _ *testSpace, dir string) {
			writeFile(t, filepath.Join(dir, MapFile), make([]byte, netmap.MaxEnvelopeSize+1), 0o644)
		}, "larger than a map"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unix && runtime.GOOS == "windows" {
				t.Skip("no modes on Windows")
			}
			s := newTestSpace(t)
			dir := s.stateDir(t, s.b, 1)
			tc.mutate(t, s, dir)
			_, err := LoadState(dir, filepath.Join(dir, MapFile))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error with %q", err, tc.want)
			}
		})
	}
}

func remove(t *testing.T, dir, name string) {
	t.Helper()
	if err := os.Remove(filepath.Join(dir, name)); err != nil {
		t.Fatal(err)
	}
}

func chmod(t *testing.T, path string, perm os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
}

func TestKeyFilesParse(t *testing.T) {
	k := NodeKeys{ID: netmap.NodeID{1, 2, 3}, Map: netmap.GenerateNodeKey(), WireGuard: netmap.GenerateWireGuardKey()}
	got, err := parseNodeKeys("node.key", []byte(nodeKeyFile(k)))
	if err != nil || got != k {
		t.Fatalf("got %v, %v", got, err)
	}
	// Unquoted values read the same.
	plain := strings.ReplaceAll(nodeKeyFile(k), `"`, "")
	if got, err := parseNodeKeys("node.key", []byte(plain)); err != nil || got != k {
		t.Fatalf("unquoted: %v, %v", got, err)
	}
	mapHex := hex.EncodeToString(k.Map[:])
	for _, tc := range []struct{ name, file, want string }{
		{"unknown field", nodeKeyFile(k) + "extra: \"1\"\n", `node.key:5: unknown field "extra"`},
		{"twice", nodeKeyFile(k) + "node-id: \"01\"\n", "node.key:5: node-id given twice"},
		{"missing", strings.Replace(nodeKeyFile(k), "map-key", "# map-key", 1), "map-key is missing"},
		{"not a field", nodeKeyFile(k) + "junk\n", "node.key:5: not a `field: value` line"},
		{"bad key", strings.Replace(nodeKeyFile(k), mapHex, mapHex[2:], 1), "map-key: must be 32 hex bytes"},
		{"zero id", strings.Replace(nodeKeyFile(k), k.ID.String(), netmap.NodeID{}.String(), 1), "node-id is zero"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseNodeKeys("node.key", []byte(tc.file))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
			if strings.Contains(err.Error(), mapHex) {
				t.Fatalf("the error quotes the private key: %v", err)
			}
		})
	}
}

func TestNodeKeysNeverPrint(t *testing.T) {
	k := NodeKeys{ID: netmap.NodeID{1}, Map: netmap.GenerateNodeKey(), WireGuard: netmap.GenerateWireGuardKey()}
	c := WorkerConfig{Keys: k, Map: []byte("map")}
	for _, s := range []string{fmt.Sprint(k), fmt.Sprintf("%v %+v %#v", k, k, k), fmt.Sprint(c), fmt.Sprintf("%+v", c)} {
		for _, secret := range [][]byte{k.Map[:], k.WireGuard[:]} {
			if strings.Contains(s, hex.EncodeToString(secret)) || bytes.Contains([]byte(s), secret) {
				t.Fatalf("a private key in %q", s)
			}
		}
	}
}

func TestWorkerConfigRoundTrip(t *testing.T) {
	s := newTestSpace(t)
	c := WorkerConfig{Keys: s.a, Trust: s.trust(), Map: s.build(t, 3), Interface: "tp0", LinkMTU: 1400}
	b, err := c.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeWorkerConfig(b)
	if err != nil {
		t.Fatal(err)
	}
	if !got.sameNode(c) || !bytes.Equal(got.Map, c.Map) || got.Interface != "tp0" || got.LinkMTU != 1400 {
		t.Fatalf("round trip: %v", got)
	}
	other := c
	other.Keys = s.b
	if other.sameNode(c) {
		t.Fatal("another node's keys count as the same node")
	}
	for _, bad := range []string{`{"version":2}`, `{"version":1,"node-id":"00"}`, `not json`} {
		if _, err := DecodeWorkerConfig([]byte(bad)); err == nil {
			t.Fatalf("decoded %s", bad)
		}
	}
	if _, err := DecodeWorkerConfig(bytes.Replace(b, []byte(hex.EncodeToString(s.a.Map[:])), []byte("zz"), 1)); err == nil ||
		!strings.Contains(err.Error(), "map-key") {
		t.Fatalf("a bad map key: %v", err)
	}
}
