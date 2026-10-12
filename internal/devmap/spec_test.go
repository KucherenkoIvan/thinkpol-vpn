package devmap

import (
	"errors"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

func TestSpecErrorsNameTheirLocation(t *testing.T) {
	const nodes = "nodes:\n  - name: s\n    kind: server\n    endpoints: [udp://192.0.2.1:4500]\n    ingress: true\n  - {name: d, kind: device}\n"
	tests := []struct {
		name, spec string
		want       []string
	}{
		{"syntax", "nodes: [\n", []string{"spec.yaml:1:"}},
		{"unknown field", "nodes:\n  - name: a\n    kind: device\n    colour: red\n", []string{`spec.yaml:4:5: unknown field "colour"`}},
		{"unknown top-level field", "nodez: []\n", []string{`spec.yaml:1:1: unknown field "nodez"`}},
		{"no nodes", "paths: []\n", []string{"spec.yaml: no nodes"}},
		{"node without a name", "nodes:\n  - kind: device\n", []string{"spec.yaml:2:5: node without a name"}},
		{"bad name", "nodes:\n  - name: Dev_A\n    kind: device\n", []string{`spec.yaml:2:11: node name "Dev_A"`}},
		{"reserved name", "nodes:\n  - name: space\n    kind: device\n", []string{`spec.yaml:2:11: node name "space" is reserved`}},
		{"duplicate name", "nodes:\n  - name: a\n    kind: device\n  - name: a\n    kind: device\n", []string{`spec.yaml:4:11: node "a" is declared twice`}},
		{"missing kind", "nodes:\n  - name: a\n", []string{"spec.yaml:2:5: a: kind is missing"}},
		{"bad kind", "nodes:\n  - name: a\n    kind: phone\n", []string{`spec.yaml:3:11: a: kind "phone" is neither server nor device`}},
		{"name is a list", "nodes:\n  - name: [a]\n    kind: device\n", []string{"spec.yaml:2:11: expected a single value"}},
		{"ipv4 network not a network address", "space:\n  ipv4: 100.64.1.1/24\n" + nodes, []string{"spec.yaml:2:9: space ipv4 100.64.1.1/24 is not a network address (100.64.1.0/24 is)"}},
		{"ipv4 network outside cgnat", "space:\n  ipv4: 10.0.0.0/8\n" + nodes, []string{"spec.yaml:2:9: space ipv4 10.0.0.0/8 is not inside 100.64.0.0/10"}},
		{"ipv6 network not a /48", "space:\n  ipv6: fd00::/64\n" + nodes, []string{"spec.yaml:2:9: space ipv6 fd00::/64 is not a /48 inside fd00::/8"}},
		{"ipv6 network not ULA", "space:\n  ipv6: 2001:db8::/48\n" + nodes, []string{"is not a /48 inside fd00::/8"}},
		{"fixed ipv4 outside", "space:\n  ipv4: 100.64.0.0/24\nnodes:\n  - name: a\n    kind: device\n    ipv4: 100.64.1.1\n", []string{"spec.yaml:6:11: a: ipv4 100.64.1.1 is not a host address in 100.64.0.0/24"}},
		{"fixed ipv4 is the network", "nodes:\n  - name: a\n    kind: device\n    ipv4: 100.64.0.0\n", []string{"spec.yaml:4:11: a: ipv4 100.64.0.0 is not a host address"}},
		{"fixed ipv4 taken", "nodes:\n  - name: a\n    kind: device\n    ipv4: 100.64.0.9\n  - name: b\n    kind: device\n    ipv4: 100.64.0.9\n", []string{"spec.yaml:7:11: b: ipv4 100.64.0.9 is taken by a"}},
		{"fixed ipv6 without network", "nodes:\n  - name: a\n    kind: device\n    ipv6: fd00::9\n", []string{"spec.yaml:4:11: a: a fixed ipv6 needs the space's ipv6 network"}},
		{"endpoint host name", "nodes:\n  - name: a\n    kind: server\n    endpoints:\n      - udp://relay.example.com:4500\n", []string{`spec.yaml:5:9: a: endpoint "udp://relay.example.com:4500": "relay.example.com:4500" is not an IP literal`}},
		{"endpoint without transport", "nodes:\n  - name: a\n    kind: server\n    endpoints: [192.0.2.1:4500]\n", []string{"spec.yaml:4:17: a: endpoint \"192.0.2.1:4500\": write transport://ip:port"}},
		{"endpoint unknown transport", "nodes:\n  - name: a\n    kind: server\n    endpoints: [tcp://192.0.2.1:4500]\n", []string{`unknown transport "tcp" (known: udp)`}},
		{"endpoint unspecified", "nodes:\n  - name: a\n    kind: server\n    endpoints: [udp://0.0.0.0:4500]\n", []string{"spec.yaml:4:17: a: endpoint udp://0.0.0.0:4500 has no address to dial"}},
		{"endpoint zone", "nodes:\n  - name: a\n    kind: server\n    endpoints: ['udp://[fe80::1%eth0]:4500']\n", []string{"no zones"}},
		{"endpoint mapped", "nodes:\n  - name: a\n    kind: server\n    endpoints: ['udp://[::ffff:192.0.2.1]:4500']\n", []string{"not IPv4-mapped IPv6"}},
		{"endpoint port 0", "nodes:\n  - name: a\n    kind: server\n    endpoints: [udp://192.0.2.1:0]\n", []string{"port 0"}},
		{"endpoint twice", "nodes:\n  - name: a\n    kind: server\n    endpoints:\n      - udp://192.0.2.1:4500\n      - udp://192.0.2.1:4500\n", []string{"spec.yaml:6:9: a: endpoint udp://192.0.2.1:4500 is listed twice"}},
		{"endpoint without listener", "nodes:\n  - name: a\n    kind: server\n    endpoints: [udp://192.0.2.1:4500]\n    listen: []\n", []string{"spec.yaml:2:5: a: endpoint udp://192.0.2.1:4500 has no udp listener of its address family"}},
		{"endpoint without listener of its family", "nodes:\n  - name: a\n    kind: server\n    endpoints: ['udp://[2001:db8::1]:4500']\n    listen: [udp://0.0.0.0:4500]\n", []string{"spec.yaml:5:14: a: endpoint udp://[2001:db8::1]:4500 has no udp listener of its address family"}},
		{"device with endpoints", "nodes:\n  - name: a\n    kind: device\n    endpoints: [udp://192.0.2.1:4500]\n", []string{"spec.yaml:4:17: a: a device has no endpoints or listeners: it dials servers"}},
		{"device with listen", "nodes:\n  - name: a\n    kind: device\n    listen: [udp://0.0.0.0:4500]\n", []string{"spec.yaml:4:14: a: a device has no endpoints"}},
		{"unset variable", "nodes:\n  - name: a\n    kind: server\n    endpoints: ['udp://${NOPE}:4500']\n", []string{"spec.yaml:4:17: ${NOPE} is not set"}},
		{"malformed variable", "nodes:\n  - name: a\n    kind: server\n    endpoints: ['udp://${1X}:4500']\n", []string{"spec.yaml:4:17: malformed variable"}},
		{"server with rules", "nodes:\n  - name: a\n    kind: server\n    rules: [default -> direct]\n", []string{"spec.yaml:2:5: a: only a device has chains and rules"}},
		{"chain to nowhere", "nodes:\n  - name: a\n    kind: device\n    chains: {out: nope}\n", []string{`spec.yaml:4:19: a: chain out: unknown node "nope"`}},
		{"bad chain name", "nodes:\n  - name: a\n    kind: device\n    chains: {Out: a}\n", []string{"spec.yaml:4:19: a: chain name"}},
		{"chain to a server without egress", nodes + "  - {name: e, kind: device, chains: {out: s}}\npaths:\n  - [e, s]\n", []string{"spec.yaml:7:43: e: chain out: s doesn't allow egress"}},
		{"chain to a stranger", "nodes:\n  - name: s\n    kind: server\n    endpoints: [udp://192.0.2.1:4500]\n    ingress: true\n    egress: true\n  - {name: d, kind: device, chains: {out: s}}\n", []string{"spec.yaml:7:43: d: chain out: s isn't a peer of d"}},
		{"bad rule", "nodes:\n  - name: a\n    kind: device\n    rules: [everything -> out]\n", []string{"spec.yaml:4:13: a: "}},
		{"path of one", nodes + "paths:\n  - [d]\n", []string{"spec.yaml:8:5: a path needs at least two nodes"}},
		{"path not a list", nodes + "paths:\n  - d > s\n", []string{"spec.yaml:8:5: a path is a list of node names"}},
		{"path unknown node", nodes + "paths:\n  - [d, x]\n", []string{`spec.yaml:8:9: unknown node "x"`}},
		{"path repeats a node", nodes + "paths:\n  - [d, s, d]\n", []string{"spec.yaml:8:12: d appears twice in one path"}},
		{"device relays", nodes + "  - name: e\n    kind: device\npaths:\n  - [s, d, e]\n", []string{"spec.yaml:10:9: d is a device and can't relay"}},
		{"same path twice", nodes + "paths:\n  - [d, s]\n  - [d, s]\n", []string{"spec.yaml:9:5: same path as line 8"}},
		{"same path reversed", nodes + "paths:\n  - [d, s]\n  - [s, d]\n", []string{"spec.yaml:9:5: same path as line 8, reversed"}},
		{"list without a name", "lists:\n  - file: ru.geoip\n" + nodes, []string{"spec.yaml:2:5: list without a name"}},
		{"list without a file", "lists:\n  - name: ru\n" + nodes, []string{"spec.yaml:2:5: list ru: file is missing"}},
		{"bad list name", "lists:\n  - {name: RU_1, file: x}\n" + nodes, []string{`spec.yaml:2:12: lists: bad list name "RU_1"`}},
		{"list twice", "lists:\n  - {name: ru, file: a}\n  - {name: ru, file: b}\n" + nodes, []string{`spec.yaml:3:12: list "ru" is declared twice`}},
		{"list field", "lists:\n  - {name: ru, file: a, kind: geoip}\n" + nodes, []string{`unknown field "kind"`}},
		{"node names an unknown list", "nodes:\n  - name: d\n    kind: device\n    lists: [ru]\n", []string{`spec.yaml:4:13: d: unknown list "ru"`}},
		{"node names a list twice", "lists:\n  - {name: ru, file: a}\nnodes:\n  - name: d\n    kind: device\n    lists: [ru, ru]\n", []string{`spec.yaml:6:17: d: list "ru" is named twice`}},
		{"ingress not a boolean", "nodes:\n  - name: s\n    kind: server\n    ingress: yes\n", []string{`spec.yaml:4:14: s: ingress "yes" is neither true nor false`}},
		{"egress not a boolean", "nodes:\n  - name: s\n    kind: server\n    egress: [true]\n", []string{"spec.yaml:4:13: expected a single value"}},
		{"device with ingress", "nodes:\n  - name: d\n    kind: device\n    ingress: true\n", []string{"spec.yaml:4:14: d: a device has no ingress setting"}},
		{"device with egress", "nodes:\n  - name: d\n    kind: device\n    egress: false\n", []string{"spec.yaml:4:13: d: a device has no egress setting"}},
		{"device dials a server with ingress off", "nodes:\n  - {name: s, kind: server, endpoints: ['udp://192.0.2.1:4500']}\n  - {name: d, kind: device}\npaths:\n  - [d, s]\n  - [s, d]\n",
			[]string{"spec.yaml:5:9: s has ingress off, so d can't connect to it", "spec.yaml:6:6: s has ingress off, so d can't connect to it"}},
		{"several errors at once", "nodes:\n  - name: a\n    kind: phone\n  - name: b\n", []string{"spec.yaml:3:11: a: kind", "spec.yaml:4:5: b: kind is missing"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseSpec("spec.yaml", []byte(tt.spec), func(string) (string, bool) { return "", false })
			if err == nil {
				t.Fatal("spec accepted")
			}
			for _, w := range tt.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q\nwant it to contain %q", err, w)
				}
			}
		})
	}
}

// An unset variable is one error, not one more for the value it leaves.
func TestUnsetVariableIsOneError(t *testing.T) {
	_, err := ParseSpec("spec.yaml", []byte("nodes:\n  - name: a\n    kind: ${KIND}\n"), nil)
	if err == nil || err.Error() != "spec.yaml:3:11: ${KIND} is not set" {
		t.Fatalf("err %v", err)
	}
}

func TestVariablesFillValues(t *testing.T) {
	spec := "nodes:\n  - name: s\n    kind: server\n    endpoints:\n      - udp://${V4}:4500\n      - 'udp://[${V6}]:${PORT}'\n"
	vars := map[string]string{"V4": "192.0.2.7", "V6": "2001:db8::7", "PORT": "4501"}
	s, err := ParseSpec("spec.yaml", []byte(spec), func(n string) (string, bool) { v, ok := vars[n]; return v, ok })
	if err != nil {
		t.Fatal(err)
	}
	got := s.Nodes[0].Endpoints
	want := []Address{
		{"udp", netip.MustParseAddrPort("192.0.2.7:4500")},
		{"udp", netip.MustParseAddrPort("[2001:db8::7]:4501")},
	}
	if !slices.Equal(got, want) {
		t.Fatalf("endpoints %v, want %v", got, want)
	}
}

func TestListenersFollowEndpoints(t *testing.T) {
	spec := `nodes:
  - name: s
    kind: server
    endpoints:
      - udp://192.0.2.1:4500
      - udp://192.0.2.2:4500
      - udp://[2001:db8::1]:4501
  - name: t
    kind: server
    endpoints: [udp://192.0.2.3:4500]
    listen: [udp://192.0.2.3:4500]
`
	s, err := ParseSpec("spec.yaml", []byte(spec), nil)
	if err != nil {
		t.Fatal(err)
	}
	derived := []Address{
		{"udp", netip.MustParseAddrPort("0.0.0.0:4500")},
		{"udp", netip.MustParseAddrPort("[::]:4501")},
	}
	if got := s.Nodes[0].Listeners; !slices.Equal(got, derived) {
		t.Errorf("derived listeners %v, want %v", got, derived)
	}
	if got := s.Nodes[1].Listeners; !slices.Equal(got, []Address{{"udp", netip.MustParseAddrPort("192.0.2.3:4500")}}) {
		t.Errorf("written listeners %v", got)
	}
}

func TestWhoDials(t *testing.T) {
	spec := `nodes:
  - name: dev
    kind: device
  - name: s2
    kind: server
    endpoints: [udp://192.0.2.2:4500]
    ingress: true
  - name: s1
    kind: server
    endpoints: [udp://192.0.2.1:4500]
    ingress: true
paths:
  - [s1, dev]
  - [dev, s2, s1]
`
	s, err := ParseSpec("spec.yaml", []byte(spec), nil)
	if err != nil {
		t.Fatal(err)
	}
	// dev has no endpoints and dials both servers; of the two servers, the
	// one declared first (s2) dials.
	links, err := Links(s)
	want := []Link{{From: 0, To: 2}, {From: 0, To: 1}, {From: 1, To: 2}}
	if err != nil || !slices.Equal(links, want) {
		t.Fatalf("links %v, %v; want %v", links, err, want)
	}
}

func TestAddressesAssignedInOrderAroundFixedOnes(t *testing.T) {
	spec := `space:
  ipv4: 100.64.7.0/29
  ipv6: fd01:2:3::/48
nodes:
  - {name: a, kind: device}
  - {name: b, kind: device, ipv4: 100.64.7.1, ipv6: "fd01:2:3::2"}
  - {name: c, kind: device}
`
	f := newFixture(t, "spec.yaml", []byte(spec), nil)
	_, secs, _ := f.sections(t, 1)
	for name, want := range map[string][2]string{
		"a": {"100.64.7.2", "fd01:2:3::1"},
		"b": {"100.64.7.1", "fd01:2:3::2"},
		"c": {"100.64.7.3", "fd01:2:3::3"},
	} {
		n := secs[name].Node
		if n.IPv4.String() != want[0] || n.IPv6.String() != want[1] {
			t.Errorf("%s: %v %v, want %v", name, n.IPv4, n.IPv6, want)
		}
	}

	full := "space:\n  ipv4: 100.64.7.0/30\nnodes:\n  - {name: a, kind: device}\n  - {name: b, kind: device}\n  - {name: c, kind: device}\n  - {name: d, kind: device}\n"
	f = newFixture(t, "spec.yaml", []byte(full), nil)
	if _, _, err := Plan(f.spec, f.keys, 1, nil); err == nil || !strings.Contains(err.Error(), "spec.yaml:7:6: d: no address left in 100.64.7.0/30") {
		t.Fatalf("err %v", err)
	}
}

// Without space.ipv6 the map uses the space's own random /48.
func TestIPv6NetworkComesFromTheSpaceKeys(t *testing.T) {
	f := labFixture(t)
	_, secs, _ := f.sections(t, 1)
	if got := secs["server-1"].Node.IPv6Network; got != f.space.IPv6Network || !f.space.IPv6Network.Contains(secs["device-a"].Node.IPv6) {
		t.Fatalf("network %v, want %v", got, f.space.IPv6Network)
	}
	f = referenceFixture(t)
	_, secs, _ = f.sections(t, 1)
	if got := secs["server-1"].Node.IPv6Network; got != netip.MustParsePrefix("fd12:3456:789a::/48") {
		t.Fatalf("the spec's network is %v", got)
	}
}

func TestReadLists(t *testing.T) {
	spec := "lists:\n  - {name: ru, file: lists/ru.geoip}\n  - {name: by, file: /abs/by.geoip}\n" +
		"nodes:\n  - name: d\n    kind: device\n    lists: [by, ru]\n  - name: s\n    kind: server\n    ingress: true\n    endpoints: [udp://192.0.2.1:4500]\npaths:\n  - [d, s]\n"
	s, err := ParseSpec("specs/spec.yaml", []byte(spec), nil)
	if err != nil {
		t.Fatal(err)
	}
	var read []string
	if err := ReadLists(s, func(path string) ([]byte, error) { read = append(read, path); return testList(path) }); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(read, []string{"specs/lists/ru.geoip", "/abs/by.geoip"}) {
		t.Errorf("read %v", read)
	}
	f := fixture{spec: s}
	f.space, _ = NewSpaceKeys(nil)
	f.nodes = map[string]NodeKeys{}
	f.keys = Keys{Space: f.space.ID, IPv6Network: f.space.IPv6Network, Signing: f.space.Signing, RecoveryKey: f.space.Trust().RecoveryKey, Nodes: map[string]NodePublic{}}
	for _, n := range s.Nodes {
		k, _ := NewNodeKeys(nil)
		f.nodes[n.Name], f.keys.Nodes[n.Name] = k, k.Public()
	}
	m, secs, _ := f.sections(t, 1)
	if h := m.Header().Blobs; len(h) != 2 || h[0].Name != "" || h[0] != unnamed(s.Lists[0].Ref) || h[1] != unnamed(s.Lists[1].Ref) {
		t.Errorf("header blobs %+v", h)
	}
	if b := secs["d"].Blobs; len(b) != 2 || b[0] != s.Lists[1].Ref || b[1] != s.Lists[0].Ref || b[0].Name != "by" {
		t.Errorf("d's blobs %+v", b)
	}
	if b := secs["s"].Blobs; len(b) != 0 {
		t.Errorf("s's blobs %+v", b)
	}

	for name, read := range map[string]func(string) ([]byte, error){
		"unreadable":   func(string) ([]byte, error) { return nil, errors.New("no such file") },
		"not a list":   func(string) ([]byte, error) { return []byte("junk"), nil },
		"same content": func(string) ([]byte, error) { return testList("x") },
	} {
		s, _ := ParseSpec("spec.yaml", []byte(spec), nil)
		if err := ReadLists(s, read); err == nil || !strings.Contains(err.Error(), "spec.yaml:") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// Two lists of 9 MiB: together past what a server holds (the size is
	// checked before the content).
	nine := func(string) ([]byte, error) { return make([]byte, 9<<20), nil }
	tooMuch, _ := ParseSpec("spec.yaml", []byte(spec), nil)
	if err := ReadLists(tooMuch, nine); err == nil || !strings.Contains(err.Error(), "list by: the lists together pass 16777216 bytes") {
		t.Errorf("lists past the total: %v", err)
	}
	unread, _ := ParseSpec("spec.yaml", []byte(spec), nil)
	if _, _, err := Plan(unread, f.keys, 1, nil); err == nil || !strings.Contains(err.Error(), "not read") {
		t.Errorf("planning unread lists: %v", err)
	}
}

func unnamed(r netmap.BlobRef) netmap.BlobRef { r.Name = ""; return r }
