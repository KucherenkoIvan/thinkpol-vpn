package devmap

import (
	"math/rand/v2"
	"os"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

// fixture is a parsed spec with deterministic keys for every node.
type fixture struct {
	spec  *Spec
	space SpaceKeys
	nodes map[string]NodeKeys
	keys  Keys
}

func newFixture(t *testing.T, file string, data []byte, vars map[string]string) fixture {
	t.Helper()
	s, err := ParseSpec(file, data, func(name string) (string, bool) { v, ok := vars[name]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	random := rand.NewChaCha8([32]byte{1})
	space, err := NewSpaceKeys(random)
	if err != nil {
		t.Fatal(err)
	}
	f := fixture{spec: s, space: space, nodes: map[string]NodeKeys{}}
	f.keys = Keys{Space: space.ID, IPv6Network: space.IPv6Network, Signing: space.Signing, RecoveryKey: space.Trust().RecoveryKey, Nodes: map[string]NodePublic{}}
	for _, n := range s.Nodes {
		k, err := NewNodeKeys(random)
		if err != nil {
			t.Fatal(err)
		}
		f.nodes[n.Name] = k
		f.keys.Nodes[n.Name] = k.Public()
	}
	return f
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The M0 lab spec, with addresses from the documentation ranges.
var labVars = map[string]string{"SERVER_1_IPV4": "192.0.2.10", "SERVER_1_IPV6": "2001:db8::10"}

func referenceFixture(t *testing.T) fixture {
	return newFixture(t, "reference.yaml", []byte(Reference), nil)
}

func labFixture(t *testing.T) fixture {
	return newFixture(t, "m0.yaml", readFile(t, "../../lab/maps/m0.yaml"), labVars)
}

// sections builds f's map, verifies it and opens every node's section.
func (f fixture) sections(t *testing.T, version uint64) (*netmap.Map, map[string]netmap.Section, Names) {
	t.Helper()
	env, err := Build(f.spec, f.keys, version, rand.NewChaCha8([32]byte{2}))
	if err != nil {
		t.Fatal(err)
	}
	m, err := netmap.Verify(env, f.space.Trust())
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]netmap.Section{}
	names := Names{}
	for _, n := range f.spec.Nodes {
		sec, err := m.Open(f.nodes[n.Name].Map)
		if err != nil {
			t.Fatalf("%s: %v", n.Name, err)
		}
		out[n.Name] = sec
		names[sec.Node.ID] = n.Name
	}
	return m, out, names
}
