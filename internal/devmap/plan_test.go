package devmap

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"maps"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

var update = flag.Bool("update", false, "rewrite the golden files")

// Each spec's map, built, verified and opened with every node's key, prints
// as its golden file: the header, then every node's section as inspect
// shows it. Review a changed golden file as a change to what nodes know.
func TestGolden(t *testing.T) {
	for _, tt := range []struct {
		golden string
		f      func(*testing.T) fixture
	}{
		{"reference.golden", referenceFixture},
		{"m0.golden", labFixture},
	} {
		t.Run(tt.golden, func(t *testing.T) {
			f := tt.f(t)
			m, secs, names := f.sections(t, 7)
			var b bytes.Buffer
			if err := DescribeHeader(&b, m); err != nil {
				t.Fatal(err)
			}
			for _, n := range f.spec.Nodes {
				b.WriteString("\n# section of " + n.Name + "\n")
				if err := DescribeSection(&b, secs[n.Name], names); err != nil {
					t.Fatal(err)
				}
			}
			path := filepath.Join("testdata", tt.golden)
			if *update {
				if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if want := readFile(t, path); !bytes.Equal(b.Bytes(), want) {
				t.Errorf("output differs from %s (go test ./internal/devmap -run TestGolden -update):\n%s", path, b.String())
			}
		})
	}
}

// A node's section names exactly the nodes it shares a path with as an end
// (its peers), its neighbours on paths (its links, first and next hops),
// and the ends of the paths it relays on (its routes); and a link's secret
// is in its two ends' sections only.
func TestSectionsHoldOnlyWhatTheirNodeNeeds(t *testing.T) {
	for _, f := range []fixture{referenceFixture(t), labFixture(t)} {
		_, secs, names := f.sections(t, 1)
		id := map[string]netmap.NodeID{}
		for nid, name := range names {
			id[name] = nid
		}
		peers, neighbours, dests := map[string]set{}, map[string]set{}, map[string]set{}
		for _, n := range f.spec.Nodes {
			peers[n.Name], neighbours[n.Name], dests[n.Name] = set{}, set{}, set{}
		}
		for _, p := range f.spec.Paths {
			name := func(i int) string { return f.spec.Nodes[p.Nodes[i]].Name }
			last := len(p.Nodes) - 1
			peers[name(0)].add(id[name(last)])
			peers[name(last)].add(id[name(0)])
			for i := range p.Nodes {
				if i > 0 {
					neighbours[name(i)].add(id[name(i-1)])
				}
				if i < last {
					neighbours[name(i)].add(id[name(i+1)])
				}
				if i > 0 && i < last {
					dests[name(i)].add(id[name(0)], id[name(last)])
				}
			}
		}

		holders := map[string][]string{}
		for name, s := range secs {
			gotPeers, gotAdjacent, gotDests := set{}, set{}, set{}
			for _, p := range s.Peers {
				gotPeers.add(p.ID)
				for _, h := range p.Paths {
					if !neighbours[name][h.FirstHop] {
						t.Errorf("%s: first hop %s is not a neighbour", name, names.Of(h.FirstHop))
					}
				}
			}
			credentials := map[string]bool{}
			for _, l := range s.Links {
				gotAdjacent.add(l.Peer)
				for _, e := range l.Endpoints {
					credentials[string(e.Credential)] = true
				}
			}
			for _, in := range s.Inbound {
				gotAdjacent.add(in.Peer)
				credentials[string(in.Credential)] = true
			}
			for _, r := range s.Routes {
				gotDests.add(r.Destination)
				for _, h := range r.NextHops {
					if !neighbours[name][h] {
						t.Errorf("%s: next hop %s is not a neighbour", name, names.Of(h))
					}
				}
			}
			for c := range credentials {
				holders[c] = append(holders[c], name)
			}
			if !maps.Equal(gotPeers, peers[name]) || !maps.Equal(gotAdjacent, neighbours[name]) || !maps.Equal(gotDests, dests[name]) {
				t.Errorf("%s: peers %v, adjacent %v, routes %v; want %v, %v, %v",
					name, gotPeers, gotAdjacent, gotDests, peers[name], neighbours[name], dests[name])
			}
		}
		for _, h := range holders {
			if len(h) != 2 || !neighbours[h[0]][id[h[1]]] {
				t.Errorf("a link secret is held by %v, want exactly the link's two ends", h)
			}
		}
		links, err := Links(f.spec)
		if err != nil {
			t.Fatal(err)
		}
		if want := len(links); len(holders) != want {
			t.Errorf("%d link secrets, want one per link: %d", len(holders), want)
		}
	}
}

type set map[netmap.NodeID]bool

func (s set) add(ids ...netmap.NodeID) {
	for _, id := range ids {
		s[id] = true
	}
}

// Paths between the same ends are alternatives in the order written, which
// is what failover follows; relays merge next hops the same way.
func TestFirstHopsFollowPathOrder(t *testing.T) {
	f := referenceFixture(t)
	_, secs, names := f.sections(t, 1)
	byName := func(name string) netmap.NodeID {
		for id, n := range names {
			if n == name {
				return id
			}
		}
		t.Fatalf("no %s", name)
		return netmap.NodeID{}
	}
	for _, p := range secs["device-a"].Peers {
		if p.ID != byName("device-b") {
			continue
		}
		got := []netmap.NodeID{}
		for _, h := range p.Paths {
			got = append(got, h.FirstHop)
		}
		if want := []netmap.NodeID{byName("server-1"), byName("server-2")}; !slices.Equal(got, want) {
			t.Fatalf("device-a's first hops to device-b %v, want server-1 then server-2", got)
		}
		return
	}
	t.Fatal("device-a has no peer device-b")
}

// Every build seals afresh with fresh secrets, but a node keeps its id and
// addresses while its keys stay the same.
func TestRebuildKeepsIdentities(t *testing.T) {
	f := labFixture(t)
	a, err := Build(f.spec, f.keys, 1, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Build(f.spec, f.keys, 2, nil)
	if err != nil {
		t.Fatal(err)
	}
	ma, _ := netmap.Verify(a, f.space.Trust())
	mb, _ := netmap.Verify(b, f.space.Trust())
	if err := netmap.Accept(ma, mb); err != nil {
		t.Fatalf("a node on the first build doesn't take the second: %v", err)
	}
	for name, k := range f.nodes {
		sa, err := ma.Open(k.Map)
		if err != nil {
			t.Fatal(err)
		}
		sb, err := mb.Open(k.Map)
		if err != nil {
			t.Fatal(err)
		}
		if sa.Node.ID != sb.Node.ID || sa.Node.IPv4 != sb.Node.IPv4 || sa.Node.IPv6 != sb.Node.IPv6 {
			t.Errorf("%s changed identity across builds", name)
		}
		if len(sa.Inbound) > 0 && bytes.Equal(sa.Inbound[0].Credential, sb.Inbound[0].Credential) {
			t.Errorf("%s: link secret reused across builds", name)
		}
	}
}

func TestPlanNeedsEveryNodesKeys(t *testing.T) {
	f := labFixture(t)
	delete(f.keys.Nodes, "device-b")
	pos := f.spec.Nodes[2].Pos
	if _, _, err := Plan(f.spec, f.keys, 1, nil); err == nil || err.Error() != fmt.Sprintf("m0.yaml:%d:%d: device-b: no public keys", pos.Line, pos.Col) {
		t.Fatalf("err %v", err)
	}
	f = labFixture(t)
	f.keys.Nodes["device-b"] = f.keys.Nodes["device-a"]
	if _, _, err := Plan(f.spec, f.keys, 1, nil); err == nil || err.Error() != fmt.Sprintf("m0.yaml:%d:%d: device-b: has the same keys as device-a", pos.Line, pos.Col) {
		t.Fatalf("err %v", err)
	}
	f = labFixture(t)
	b := f.keys.Nodes["device-b"]
	b.ID = f.keys.Nodes["device-a"].ID
	f.keys.Nodes["device-b"] = b
	if _, _, err := Plan(f.spec, f.keys, 1, nil); err == nil || err.Error() != fmt.Sprintf("m0.yaml:%d:%d: device-b: has the same node id as device-a", pos.Line, pos.Col) {
		t.Fatalf("err %v", err)
	}
}

func TestReferenceIsTheFormat(t *testing.T) {
	// Every field the parser knows appears in the reference spec.
	for _, field := range []string{"space:", "ipv4:", "ipv6:", "lists:", "file:", "nodes:", "name:", "kind:", "endpoints:", "listen:", "ingress:", "egress:", "paths:", "rules:", "chains:", "exit:", "presets:", "domestic:", "chain:"} {
		if !bytes.Contains([]byte(Reference), []byte("\n"+field)) && !bytes.Contains([]byte(Reference), []byte(" "+field)) {
			t.Errorf("reference spec lacks %s", field)
		}
	}
}

const fourServers = `nodes:
  - {name: a, kind: device}
  - {name: b, kind: device}
  - {name: c, kind: device}
  - name: s1
    kind: server
    endpoints: [udp://192.0.2.1:4500]
    ingress: true
  - name: s2
    kind: server
    endpoints: [udp://192.0.2.2:4500]
    ingress: true
`

// Two paths crossing the same relays in opposite directions would let s1
// and s2 hand a packet for b back and forth.
func TestForwardingLoopsAreRefused(t *testing.T) {
	spec := fourServers + "paths:\n  - [a, s1, s2, b]\n  - [c, s2, s1, b]\n"
	f := newFixture(t, "spec.yaml", []byte(spec), nil)
	_, _, err := Plan(f.spec, f.keys, 1, nil)
	if err == nil || !strings.Contains(err.Error(), "spec.yaml:15:5: the paths on lines 14 and 15 make a forwarding loop toward b: s1 → s2 → s1") {
		t.Fatalf("err %v", err)
	}

	// The same relays in the same direction, or toward different
	// destinations, are fine.
	for _, paths := range []string{
		"  - [a, s1, s2, b]\n  - [c, s1, s2, b]\n",
		"  - [a, s1, s2, b]\n  - [c, s2, s1, a]\n",
		"  - [a, s1, s2, b]\n  - [a, s2, b]\n  - [c, s2, s1, a]\n",
	} {
		f := newFixture(t, "spec.yaml", []byte(fourServers+"paths:\n"+paths), nil)
		if _, _, err := Plan(f.spec, f.keys, 1, nil); err != nil {
			t.Errorf("%q: %v", paths, err)
		}
	}
}

// What `dev map inspect` shows of a device's section never has the address
// of a server with ingress off, even one the device reaches through relays;
// the settings reach each server's own section.
func TestDevicesNeverSeeAnIngressOffServer(t *testing.T) {
	f := referenceFixture(t)
	_, secs, names := f.sections(t, 1)
	hidden := 0
	for _, n := range f.spec.Nodes {
		if n.Kind != netmap.NodeServer {
			continue
		}
		if got := secs[n.Name].Node; got.AllowIngress != n.Ingress || got.AllowEgress != n.Egress {
			t.Errorf("%s: section has ingress %v, egress %v; spec %v, %v", n.Name, got.AllowIngress, got.AllowEgress, n.Ingress, n.Egress)
		}
		if n.Ingress {
			continue
		}
		hidden++
		for _, d := range f.spec.Nodes {
			if d.Kind != netmap.NodeDevice {
				continue
			}
			var b bytes.Buffer
			if err := DescribeSection(&b, secs[d.Name], names); err != nil {
				t.Fatal(err)
			}
			for _, e := range n.Endpoints {
				if strings.Contains(b.String(), e.AddrPort.Addr().String()) {
					t.Errorf("%s's section has %s's address %v:\n%s", d.Name, n.Name, e.AddrPort.Addr(), b.String())
				}
			}
		}
	}
	if hidden == 0 {
		t.Fatal("the reference spec has no server with ingress off")
	}
}

func TestDevicesCantBeLinked(t *testing.T) {
	f := newFixture(t, "spec.yaml", []byte(fourServers+"paths:\n  - [a, b]\n"), nil)
	if _, _, err := Plan(f.spec, f.keys, 1, nil); err == nil || err.Error() != "spec.yaml:14:9: neither a nor b has endpoints, so neither can dial the other" {
		t.Fatalf("err %v", err)
	}
}

// Every device's section gets the space's rules and chains, so a device
// without a path to a chain's exit can't be planned.
func TestDevicesNeedAPathToEveryChainsExit(t *testing.T) {
	spec := `nodes:
  - {name: a, kind: device}
  - {name: b, kind: device}
  - name: s
    kind: server
    endpoints: [udp://192.0.2.1:4500]
    ingress: true
    egress: true
paths:
  - [a, s]
  - [b, s, a]
rules:
  - default -> chain:out
chains:
  - {name: out, exit: s}
`
	f := newFixture(t, "spec.yaml", []byte(spec), nil)
	if _, _, err := Plan(f.spec, f.keys, 1, nil); err == nil || !strings.Contains(err.Error(), "b: no path to s, the exit of chain out") {
		t.Fatalf("err %v", err)
	}
}

// A geoip rule goes to every device, so every device names its list.
func TestDevicesNeedTheListsOfGeoIPRules(t *testing.T) {
	spec := `lists:
  - {name: ru, file: ru.geoip}
nodes:
  - {name: a, kind: device, lists: [ru]}
  - {name: b, kind: device}
  - name: s
    kind: server
    endpoints: [udp://192.0.2.1:4500]
    ingress: true
    egress: true
paths:
  - [a, s]
  - [b, s]
rules:
  - geoip:ru -> direct
  - default -> chain:out
chains:
  - {name: out, exit: s}
`
	f := newFixture(t, "spec.yaml", []byte(spec), nil)
	if _, _, err := Plan(f.spec, f.keys, 1, nil); err == nil || !strings.Contains(err.Error(), "b: rule geoip:ru -> direct needs the list") {
		t.Fatalf("err %v", err)
	}
	f = newFixture(t, "spec.yaml", []byte(strings.Replace(spec, "{name: b, kind: device}", "{name: b, kind: device, lists: [ru]}", 1)), nil)
	if _, err := Build(f.spec, f.keys, 1, nil); err != nil {
		t.Fatal(err)
	}
}

func TestVersions(t *testing.T) {
	f := labFixture(t)
	for _, v := range []uint64{0, netmap.MaxVersion + 1} {
		if _, err := Build(f.spec, f.keys, v, nil); err == nil || !strings.Contains(err.Error(), fmt.Sprintf("map version %d: must be from 1 to %d", v, uint64(netmap.MaxVersion))) {
			t.Errorf("version %d: %v", v, err)
		}
	}
	if _, err := Build(f.spec, f.keys, netmap.MaxVersion, nil); err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1_800_000_000, 0)
	future, err := Build(f.spec, f.keys, 1_900_000_000, nil)
	if err != nil {
		t.Fatal(err)
	}
	past, err := Build(f.spec, f.keys, 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	foreign := labFixture(t)
	foreign.keys.Signing = ed25519.NewKeyFromSeed(make([]byte, 32))
	other, err := Build(foreign.spec, foreign.keys, 1_900_000_000, nil)
	if err != nil {
		t.Fatal(err)
	}
	trust := f.keys.Trust()
	for name, tt := range map[string]struct {
		previous []byte
		want     uint64
	}{
		"no map":          {nil, 1_800_000_000},
		"older map":       {past, 1_800_000_000},
		"newer map":       {future, 1_900_000_001},
		"another space's": {other, 1_800_000_000},
		"not a map":       {[]byte("junk"), 1_800_000_000},
	} {
		if got := NextVersion(now, tt.previous, trust); got != tt.want {
			t.Errorf("%s: %d, want %d", name, got, tt.want)
		}
	}
	if !bytes.Equal(trust.SigningKey, f.space.Trust().SigningKey) || !bytes.Equal(trust.RecoveryKey, f.space.Trust().RecoveryKey) || trust.SpaceID != f.space.ID {
		t.Fatal("Keys.Trust differs from the space's")
	}
}

// Inspect marks a device's link that a server with ingress off refuses: no
// map Build makes has one, but a map is read as it is.
func TestInspectMarksRefusedLinks(t *testing.T) {
	s := netmap.Section{
		MinReader: 1,
		Node:      netmap.NodeSettings{ID: netmap.NodeID{1}, Kind: netmap.NodeServer, AllowEgress: true},
		Inbound: []netmap.InboundLink{
			{Peer: netmap.NodeID{2}, PeerKind: netmap.NodeServer, Transport: "udp", Credential: []byte{1}},
			{Peer: netmap.NodeID{3}, PeerKind: netmap.NodeDevice, Transport: "udp", Credential: []byte{2}},
		},
	}
	var b bytes.Buffer
	if err := DescribeSection(&b, s, Names{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"ingress: off, egress: on\nmin reader: 1\n",
		"0200000000000000, server\n",
		"0300000000000000, device (refused: ingress off)\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
}

// Builds with one secrets seed give every link the same secret, whatever
// else changed; without one, fresh secrets every time.
func TestSeededSecretsRepeat(t *testing.T) {
	f := referenceFixture(t)
	f.spec.Lab = true
	// By dialer and dialed node, each link's credentials.
	type link struct{ from, to netmap.NodeID }
	secrets := func(s *Spec, from Secrets) map[link][][]byte {
		c, _, err := Plan(s, f.keys, 1, from)
		if err != nil {
			t.Fatal(err)
		}
		out := map[link][][]byte{}
		for _, r := range c.Recipients {
			for _, l := range r.Section.Links {
				for _, e := range l.Endpoints {
					k := link{r.Section.Node.ID, l.Peer}
					out[k] = append(out[k], e.Credential)
				}
			}
		}
		return out
	}
	same := func(a, b map[link][][]byte) bool {
		return maps.EqualFunc(a, b, func(x, y [][]byte) bool { return slices.EqualFunc(x, y, bytes.Equal) })
	}
	a := secrets(f.spec, seeded(t, f.spec, "lab"))
	if len(a) == 0 || !same(a, secrets(f.spec, seeded(t, f.spec, "lab"))) {
		t.Fatal("one seed, different secrets")
	}
	if same(a, secrets(f.spec, seeded(t, f.spec, "other"))) || same(a, secrets(f.spec, nil)) {
		t.Fatal("secrets repeat without the seed")
	}
	// A path fewer: the links that remain keep their secrets. (Not the
	// paths the chain's exit needs.)
	var kept map[link][][]byte
	for i := range f.spec.Paths {
		fewer := *f.spec
		fewer.Paths = slices.Delete(slices.Clone(f.spec.Paths), i, i+1)
		if _, _, err := Plan(&fewer, f.keys, 1, nil); err != nil {
			continue
		}
		if k := secrets(&fewer, seeded(t, f.spec, "lab")); len(k) < len(a) {
			kept = k
			break
		}
	}
	if kept == nil {
		t.Fatal("no path of the reference spec can go without a link going too")
	}
	for l, creds := range kept {
		if !slices.EqualFunc(creds, a[l], bytes.Equal) {
			t.Fatalf("the link %v changed its secret", l)
		}
	}
}

func seeded(t *testing.T, s *Spec, seed string) Secrets {
	t.Helper()
	secrets, err := InsecureSeededSecrets(s, seed)
	if err != nil {
		t.Fatal(err)
	}
	return secrets
}

// A secrets seed is refused for any spec that doesn't say `lab: true`,
// and saying it changes nothing in the map.
func TestASecretsSeedNeedsALabSpec(t *testing.T) {
	f := referenceFixture(t)
	if f.spec.Lab {
		t.Fatal("the reference spec is a lab's")
	}
	if _, err := InsecureSeededSecrets(f.spec, "lab"); !errors.Is(err, ErrNotLab) {
		t.Fatalf("a seed for a spec that isn't a lab's: %v", err)
	}
	plan := func(s *Spec) netmap.Contents {
		c, _, err := Plan(s, f.keys, 1, RandomSecrets(rand.NewChaCha8([32]byte{3})))
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	lab := *f.spec
	lab.Lab = true
	if !reflect.DeepEqual(plan(f.spec), plan(&lab)) {
		t.Error("lab: true changed the map")
	}
	if _, err := InsecureSeededSecrets(&lab, "lab"); err != nil {
		t.Errorf("a seed for a lab spec: %v", err)
	}

	for text, want := range map[string]bool{"lab: true\n": true, "lab: false\n": false, "": false} {
		s, err := ParseSpec("x.yaml", []byte(text+"nodes:\n  - name: a\n    kind: device\n"), nil)
		if err != nil || s.Lab != want {
			t.Errorf("%q: lab %v, %v", text, s != nil && s.Lab, err)
		}
	}
	for _, text := range []string{"lab: yes\n", "lab: ${LAB}\n"} {
		_, err := ParseSpec("x.yaml", []byte(text+"nodes:\n  - name: a\n    kind: device\n"), func(string) (string, bool) { return "true", true })
		if err == nil || !strings.Contains(err.Error(), "neither true nor false") {
			t.Errorf("%q: %v", text, err)
		}
	}
}
