package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/devmap"
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
		"server-1": {"node: ", " (server-1)\nkind: server\n", "listeners:\n  - udp://0.0.0.0:4500\n  - udp://[::]:4500\n", "links: none", " (device-a), device\n", " (device-b), device\n", "routes:\n"},
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

func TestDevMapInspectRejectsTamperedMaps(t *testing.T) {
	dir := t.TempDir()
	keys, mapFile := filepath.Join(dir, "keys"), filepath.Join(dir, "map.bin")
	spec := filepath.Join(dir, "spec.yaml")
	if err := os.WriteFile(spec, []byte("nodes:\n  - name: s\n    kind: server\n    endpoints: [udp://192.0.2.1:4500]\n  - {name: d, kind: device}\npaths:\n  - [d, s]\n"), 0o644); err != nil {
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
	for _, path := range []string{"dev keygen space", "dev keygen node", "dev map build", "dev map inspect", "dev map spec"} {
		if !strings.Contains(stdout, path+"  ") {
			t.Errorf("dev -h doesn't list %s:\n%s", path, stdout)
		}
	}
}
