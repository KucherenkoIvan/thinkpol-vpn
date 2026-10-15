package main

import (
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/devmap"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

func mustRunCLI(t *testing.T, args ...string) string {
	t.Helper()
	code, stdout, stderr := runCLI(t, args...)
	if code != 0 {
		t.Fatalf("thinkpol %s: exit %d\n%s", strings.Join(args, " "), code, stderr)
	}
	return stdout
}

// The lab's way to make its M0 map: keys, the committed spec with the
// servers' addresses from the environment, build, inspect on every node.
func TestDevMapLabWorkflow(t *testing.T) {
	dir := t.TempDir()
	keys, mapFile := filepath.Join(dir, "keys"), filepath.Join(dir, "map.bin")
	t.Setenv("SERVER_1_IPV4", "192.0.2.10")
	t.Setenv("SERVER_1_IPV6", "2001:db8::10")

	mustRunCLI(t, "dev", "keygen", "space", "-out", keys)
	mustRunCLI(t, "dev", "keygen", "node", "-out", keys, "server-1", "device-a", "device-b")
	out := mustRunCLI(t, "dev", "map", "build", "-keys", keys, "-out", mapFile, "-version", "5", "../../lab/maps/m0.yaml")
	if !strings.Contains(out, "map version 5") || !strings.Contains(out, "3 nodes") {
		t.Fatalf("build said %q", out)
	}

	header := mustRunCLI(t, "dev", "map", "inspect", "-keys", keys, mapFile)
	if !strings.HasPrefix(header, "valid map") || !strings.Contains(header, "version: 5\n") || !strings.Contains(header, "sections: 8\n") || strings.Contains(header, "node:") {
		t.Fatalf("header:\n%s", header)
	}
	for node, want := range map[string][]string{
		"server-1": {"node: ", " (server-1)\nkind: server\ningress: on, egress: off\nmin reader: 1\n", "listeners:\n  - udp://0.0.0.0:4500\n  - udp://[::]:4500\n", "links: none", " (device-a), device\n", " (device-b), device\n", "routes:\n"},
		"device-a": {" (device-a)\nkind: device\n", "udp://192.0.2.10:4500, credential 32 bytes", "udp://[2001:db8::10]:4500", "inbound: none", "routes: none", "(device-b)"},
		"device-b": {" (device-b)\nkind: device\n", "udp://192.0.2.10:4500", "inbound: none", "routes: none", "(device-a)"},
	} {
		out := mustRunCLI(t, "dev", "map", "inspect", "-keys", keys, "-node-key", filepath.Join(keys, node+".key"), mapFile)
		section := out[strings.Index(out, "\nsection for "):]
		for _, w := range want {
			if !strings.Contains(section, w) {
				t.Errorf("%s's section lacks %q:\n%s", node, w, section)
			}
		}
	}

	// A node key the map has no section for.
	other := filepath.Join(dir, "other")
	mustRunCLI(t, "dev", "keygen", "node", "-out", other, "stranger")
	if code, _, stderr := runCLI(t, "dev", "map", "inspect", "-keys", keys, "-node-key", filepath.Join(other, "stranger.key"), mapFile); code != 1 || !strings.Contains(stderr, "no section for this node key") {
		t.Errorf("stranger's key: exit %d, %s", code, stderr)
	}
	// The map checked against another space's keys.
	mustRunCLI(t, "dev", "keygen", "space", "-out", other)
	if code, _, stderr := runCLI(t, "dev", "map", "inspect", "-keys", other, mapFile); code != 1 || !strings.Contains(stderr, "is not a valid map") {
		t.Errorf("other space: exit %d, %s", code, stderr)
	}
}

func TestDevMapRotate(t *testing.T) {
	dir := t.TempDir()
	keys, mapFile := filepath.Join(dir, "keys"), filepath.Join(dir, "map.bin")
	t.Setenv("SERVER_1_IPV4", "192.0.2.10")
	t.Setenv("SERVER_1_IPV6", "2001:db8::10")
	mustRunCLI(t, "dev", "keygen", "space", "-out", keys)
	mustRunCLI(t, "dev", "keygen", "node", "-out", keys, "server-1", "device-a", "device-b")
	mustRunCLI(t, "dev", "map", "build", "-keys", keys, "-out", mapFile, "-version", "5", "../../lab/maps/m0.yaml")
	first := readTestFile(t, mapFile)

	// A rotation replaces a deployed map: with none there, it says so
	// instead of building.
	absent := filepath.Join(dir, "absent.bin")
	if code, _, stderr := runCLI(t, "dev", "map", "rotate", "-keys", keys, "-out", absent, "../../lab/maps/m0.yaml"); code != 1 || !strings.Contains(stderr, "the first build is dev map build") || !strings.Contains(stderr, absent) {
		t.Fatalf("no map to rotate: exit %d, %s", code, stderr)
	}
	if _, err := os.Stat(absent); !os.IsNotExist(err) {
		t.Error("the failed rotation wrote a map")
	}

	// The map at -out must be of the space whose keys rotate it.
	other := filepath.Join(dir, "other")
	mustRunCLI(t, "dev", "keygen", "space", "-out", other)
	mustRunCLI(t, "dev", "keygen", "node", "-out", other, "server-1", "device-a", "device-b")
	otherMap := filepath.Join(dir, "other.bin")
	mustRunCLI(t, "dev", "map", "build", "-keys", other, "-out", otherMap, "../../lab/maps/m0.yaml")
	if code, _, stderr := runCLI(t, "dev", "map", "rotate", "-keys", keys, "-out", otherMap, "../../lab/maps/m0.yaml"); code != 1 || !strings.Contains(stderr, "is not a valid map of space") {
		t.Fatalf("another space's map: exit %d, %s", code, stderr)
	}

	out := mustRunCLI(t, "dev", "map", "rotate", "-keys", keys, "-out", mapFile, "../../lab/maps/m0.yaml")
	if !strings.Contains(out, "rotate: copy "+mapFile) || !strings.Contains(out, "server-1, device-a, device-b") || !strings.Contains(out, "map poll or on SIGHUP") {
		t.Fatalf("rotate said %q", out)
	}

	rotated := readTestFile(t, mapFile)
	a, err := netmap.Verify(first, devmapTrust(t, keys))
	if err != nil {
		t.Fatal(err)
	}
	b, err := netmap.Verify(rotated, devmapTrust(t, keys))
	if err != nil {
		t.Fatal(err)
	}
	if b.Header().Version <= a.Header().Version {
		t.Fatalf("rotated to version %d, was %d", b.Header().Version, a.Header().Version)
	}
	link := func(m *netmap.Map) []byte {
		t.Helper()
		k, err := devmap.ReadNodeKey(filepath.Join(keys, "device-a.key"))
		if err != nil {
			t.Fatal(err)
		}
		sec, err := m.Open(k.Map)
		if err != nil {
			t.Fatal(err)
		}
		if len(sec.Links) != 1 || len(sec.Links[0].Endpoints) == 0 {
			t.Fatalf("device-a's section: %+v", sec)
		}
		return sec.Links[0].Endpoints[0].Credential
	}
	if slices.Equal(link(a), link(b)) {
		t.Error("the rotation left device-a's link credential")
	}
	// The nodes' keys still open their sections, under the same names.
	if section := mustRunCLI(t, "dev", "map", "inspect", "-keys", keys, "-node-key", filepath.Join(keys, "device-a.key"), mapFile); !strings.Contains(section, "(device-a)") {
		t.Fatalf("device-a's section after the rotation:\n%s", section)
	}
}

func TestDevMapInspectRejectsTamperedMaps(t *testing.T) {
	dir := t.TempDir()
	keys, mapFile := filepath.Join(dir, "keys"), filepath.Join(dir, "map.bin")
	spec := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(spec, []byte("nodes:\n  - name: s\n    kind: server\n    endpoints: [udp://192.0.2.1:4500]\n    ingress: true\n  - {name: d, kind: device}\npaths:\n  - [d, s]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustRunCLI(t, "dev", "keygen", "space", "-out", keys)
	mustRunCLI(t, "dev", "keygen", "node", "-out", keys, "s", "d")
	mustRunCLI(t, "dev", "map", "build", "-keys", keys, "-out", mapFile, spec)
	original, err := os.ReadFile(mapFile)
	if err != nil {
		t.Fatal(err)
	}
	mustRunCLI(t, "dev", "map", "inspect", "-keys", keys, mapFile)

	// A byte in the header, one in a sealed section, one in the signature,
	// and a truncated map.
	for name, tamper := range map[string]func([]byte) []byte{
		"header":    func(b []byte) []byte { b[20] ^= 1; return b },
		"section":   func(b []byte) []byte { b[len(b)/2] ^= 0x80; return b },
		"signature": func(b []byte) []byte { b[len(b)-1] ^= 1; return b },
		"truncated": func(b []byte) []byte { return b[:len(b)-1] },
	} {
		tampered := filepath.Join(dir, name+".bin")
		if err := os.WriteFile(tampered, tamper(append([]byte(nil), original...)), 0o644); err != nil {
			t.Fatal(err)
		}
		code, stdout, stderr := runCLI(t, "dev", "map", "inspect", "-keys", keys, "-node-key", filepath.Join(keys, "d.key"), tampered)
		if code != 1 || !strings.Contains(stderr, "is not a valid map") || stdout != "" {
			t.Errorf("%s: exit %d, stdout %q, stderr %q", name, code, stdout, stderr)
		}
	}
}

func TestDevMapBuildNamesSpecLocations(t *testing.T) {
	dir := t.TempDir()
	spec := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(spec, []byte("nodes:\n  - name: s\n    kind: server\n    endpoints: [udp://relay.example.com:4500]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runCLI(t, "dev", "map", "build", "-keys", dir, spec)
	if code != 1 || !strings.Contains(stderr, spec+":4:17: s: endpoint") || !strings.Contains(stderr, "not an IP literal") {
		t.Fatalf("exit %d, %s", code, stderr)
	}
}

// -insecure-secrets-seed is refused unless the spec itself says lab: true.
func TestDevMapBuildSeedNeedsALabSpec(t *testing.T) {
	dir := t.TempDir()
	keys := filepath.Join(dir, "keys")
	mustRunCLI(t, "dev", "keygen", "space", "-out", keys)
	mustRunCLI(t, "dev", "keygen", "node", "-out", keys, "s", "d")
	const nodes = "nodes:\n  - name: s\n    kind: server\n    endpoints: [udp://192.0.2.1:4500]\n    ingress: true\n  - name: d\n    kind: device\npaths:\n  - [d, s]\n"
	for name, c := range map[string]struct {
		spec string
		ok   bool
	}{
		"no lab":    {nodes, false},
		"lab false": {"lab: false\n" + nodes, false},
		"lab true":  {"lab: true\n" + nodes, true},
	} {
		spec := filepath.Join(dir, strings.ReplaceAll(name, " ", "-")+".yaml")
		if err := os.WriteFile(spec, []byte(c.spec), 0o644); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := runCLI(t, "dev", "map", "build", "-keys", keys, "-out", filepath.Join(dir, "map.bin"), "-insecure-secrets-seed", "x", spec)
		switch {
		case c.ok && code != 0:
			t.Errorf("%s: exit %d, %s", name, code, stderr)
		case !c.ok && (code != 1 || !strings.Contains(stderr, "lab: true")):
			t.Errorf("%s: exit %d, %s", name, code, stderr)
		}
	}
}

func TestDevKeygenNeverReplacesKeys(t *testing.T) {
	keys := filepath.Join(t.TempDir(), "keys")
	mustRunCLI(t, "dev", "keygen", "space", "-out", keys)
	mustRunCLI(t, "dev", "keygen", "node", "-out", keys, "a")
	if code, _, stderr := runCLI(t, "dev", "keygen", "space", "-out", keys); code != 1 || !strings.Contains(stderr, "never replaced") {
		t.Errorf("space again: exit %d, %s", code, stderr)
	}
	if code, _, stderr := runCLI(t, "dev", "keygen", "node", "-out", keys, "b", "a"); code != 1 || !strings.Contains(stderr, "never replaced") {
		t.Errorf("node again: exit %d, %s", code, stderr)
	}
	if code, _, stderr := runCLI(t, "dev", "keygen", "node", "-out", keys, "c", "c"); code != 1 || !strings.Contains(stderr, "named twice") {
		t.Errorf("duplicate name: exit %d, %s", code, stderr)
	}
	if code, _, stderr := runCLI(t, "dev", "keygen", "node", "-out", keys, "c", "../d"); code != 1 || !strings.Contains(stderr, "node name") {
		t.Errorf("bad name: exit %d, %s", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(keys, "c.key")); !os.IsNotExist(err) {
		t.Error("keys written before every name was checked")
	}
	if code, _, _ := runCLI(t, "dev", "keygen", "node", "-out", keys); code != 2 {
		t.Errorf("no names: exit %d", code)
	}
}

func TestDevMapSpecPrintsTheFormat(t *testing.T) {
	if out := mustRunCLI(t, "dev", "map", "spec"); out != devmap.Reference {
		t.Fatal("dev map spec doesn't print the reference spec")
	}
}

func TestDevCommandsAreLabelledAsDevelopmentTooling(t *testing.T) {
	for path, c := range commands {
		if strings.HasPrefix(path, "dev ") && !strings.HasPrefix(c.summary, "development tooling: ") {
			t.Errorf("%s: summary %q", path, c.summary)
		}
	}
	_, stdout, _ := runCLI(t, "dev", "-h")
	for _, path := range []string{"dev keygen space", "dev keygen node", "dev map build", "dev map inspect", "dev map rotate", "dev map spec"} {
		if !strings.Contains(stdout, path+"  ") {
			t.Errorf("dev -h doesn't list %s:\n%s", path, stdout)
		}
	}
}

// No command prints a private key or a link secret, whatever it does,
// errors included.
func TestDevCommandsNeverPrintSecrets(t *testing.T) {
	dir := t.TempDir()
	keys, offline, mapFile := filepath.Join(dir, "keys"), filepath.Join(dir, "offline"), filepath.Join(dir, "map.bin")
	t.Setenv("SERVER_1_IPV4", "192.0.2.10")
	t.Setenv("SERVER_1_IPV6", "2001:db8::10")
	var outputs []string
	runAll := func(args ...string) {
		_, stdout, stderr := runCLI(t, args...)
		outputs = append(outputs, stdout, stderr)
	}
	nodes := []string{"server-1", "device-a", "device-b"}
	runAll("dev", "keygen", "space", "-out", keys, "-recovery-out", offline)
	runAll(append([]string{"dev", "keygen", "node", "-out", keys}, nodes...)...)
	runAll("dev", "keygen", "space", "-out", keys)            // refused: exists
	runAll("dev", "keygen", "node", "-out", keys, "device-a") // refused: exists
	runAll("dev", "map", "build", "-keys", keys, "-out", mapFile, "../../lab/maps/m0.yaml")
	runAll("dev", "map", "build", "-keys", keys, "-out", mapFile, "-version", "99999999999999999", "../../lab/maps/m0.yaml")
	runAll("dev", "map", "rotate", "-keys", keys, "-out", mapFile, "../../lab/maps/m0.yaml")
	runAll("dev", "map", "inspect", "-keys", keys, mapFile)
	for _, n := range nodes {
		runAll("dev", "map", "inspect", "-keys", keys, "-node-key", filepath.Join(keys, n+".key"), mapFile)
	}
	runAll("dev", "map", "inspect", "-keys", keys, "-node-key", filepath.Join(keys, "server-1.pub"), mapFile) // a public file as a key
	runAll("dev", "map", "spec")

	space, err := devmap.ReadSpaceKeys(filepath.Join(keys, devmap.SpaceKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	rec, err := os.ReadFile(filepath.Join(offline, devmap.RecoveryKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	recoverySeed := strings.Trim(strings.TrimSpace(string(rec[strings.LastIndex(string(rec), ":")+1:])), `"`)
	secrets := map[string][]byte{"signing key": space.Signing.Seed()}
	if secrets["recovery key"], err = hex.DecodeString(recoverySeed); err != nil {
		t.Fatal(err)
	}
	m, err := netmap.Verify(readTestFile(t, mapFile), devmapTrust(t, keys))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range nodes {
		k, err := devmap.ReadNodeKey(filepath.Join(keys, n+".key"))
		if err != nil {
			t.Fatal(err)
		}
		secrets[n+" map key"], secrets[n+" WireGuard key"] = k.Map[:], k.WireGuard[:]
		sec, err := m.Open(k.Map)
		if err != nil {
			t.Fatal(err)
		}
		for _, in := range sec.Inbound {
			secrets[n+" link secret from "+in.Peer.String()] = in.Credential
		}
	}
	all := strings.ToLower(strings.Join(outputs, "\n"))
	for what, b := range secrets {
		h := hex.EncodeToString(b)
		if strings.Contains(all, h[:16]) || strings.Contains(all, base64.StdEncoding.EncodeToString(b)[:16]) {
			t.Errorf("an output shows the %s", what)
		}
	}
}

func readTestFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func devmapTrust(t *testing.T, keys string) netmap.Trust {
	t.Helper()
	trust, err := devmap.ReadTrust(filepath.Join(keys, devmap.TrustFile))
	if err != nil {
		t.Fatal(err)
	}
	return trust
}

func TestDevMapBuildVersions(t *testing.T) {
	dir := t.TempDir()
	keys, mapFile := filepath.Join(dir, "keys"), filepath.Join(dir, "map.bin")
	t.Setenv("SERVER_1_IPV4", "192.0.2.10")
	t.Setenv("SERVER_1_IPV6", "2001:db8::10")
	mustRunCLI(t, "dev", "keygen", "space", "-out", keys)
	mustRunCLI(t, "dev", "keygen", "node", "-out", keys, "server-1", "device-a", "device-b")
	if code, _, stderr := runCLI(t, "dev", "map", "build", "-keys", keys, "-out", mapFile, "-version", "9007199254740993", "../../lab/maps/m0.yaml"); code != 1 || !strings.Contains(stderr, "map version 9007199254740993: must be from 1 to 9007199254740992") {
		t.Fatalf("too high a version: exit %d, %s", code, stderr)
	}
	// A map from the future (another clock, a hand-set version) is followed
	// by one past it, so nodes take the rebuild.
	mustRunCLI(t, "dev", "map", "build", "-keys", keys, "-out", mapFile, "-version", "9000000000000", "../../lab/maps/m0.yaml")
	if out := mustRunCLI(t, "dev", "map", "build", "-keys", keys, "-out", mapFile, "../../lab/maps/m0.yaml"); !strings.Contains(out, "map version 9000000000001 ") {
		t.Fatalf("rebuild: %s", out)
	}
}
