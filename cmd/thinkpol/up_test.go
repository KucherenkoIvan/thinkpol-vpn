package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/devmap"
)

// m0State makes the lab's M0 keys and map and lays out node's state
// directory the way TP-012 does: its own key, the space's trust, the map.
func m0State(t *testing.T, node string) (state, keys string) {
	t.Helper()
	dir := tempDir(t)
	keys, mapFile := filepath.Join(dir, "keys"), filepath.Join(dir, "map.bin")
	t.Setenv("SERVER_1_IPV4", "192.0.2.10")
	t.Setenv("SERVER_1_IPV6", "2001:db8::10")
	mustRunCLI(t, "dev", "keygen", "space", "-out", keys)
	mustRunCLI(t, "dev", "keygen", "node", "-out", keys, "server-1", "device-a", "device-b")
	mustRunCLI(t, "dev", "map", "build", "-keys", keys, "-out", mapFile, "../../lab/maps/m0.yaml")
	state = filepath.Join(dir, "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	for from, to := range map[string]string{
		filepath.Join(keys, node+".key"):      agent.NodeKeyFile,
		filepath.Join(keys, devmap.TrustFile): agent.TrustFile,
		mapFile:                               agent.MapFileName,
	} {
		perm := os.FileMode(0o644)
		if to == agent.NodeKeyFile {
			perm = 0o600
		}
		if err := os.WriteFile(filepath.Join(state, to), readTestFile(t, from), perm); err != nil {
			t.Fatal(err)
		}
	}
	return state, keys
}

// `thinkpol up` reads what `dev keygen` and `dev map build` write, and
// picks each node's mode from its kind.
func TestUpReadsTheDevTooling(t *testing.T) {
	for node, mode := range map[string]agent.Mode{"server-1": agent.ModeServer, "device-a": agent.ModeDevice} {
		state, _ := m0State(t, node)
		cfg := agent.Config{StateDir: state, Mode: agent.ModeAuto, LogLevel: "info", Interface: "thinkpol0", LinkMTU: 1500, MapPoll: 5e9}
		n, err := agent.Prepare(cfg, agent.Logs{})
		if err != nil {
			t.Fatal(err)
		}
		if n.Mode() != mode {
			t.Errorf("%s runs in %s mode, want %s", node, n.Mode(), mode)
		}
	}
}

func TestUpRefusesAnInvalidMap(t *testing.T) {
	state, keys := m0State(t, "device-a")
	path := filepath.Join(state, agent.MapFileName)
	env := readTestFile(t, path)
	env[len(env)/2] ^= 1
	if err := os.WriteFile(path, env, 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := runCLI(t, "up", "-state", state)
	if code != 1 || !strings.Contains(stderr, "is not a valid map") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	noSecrets(t, keys, stdout+stderr)
}

func TestUpRefusesAnUnsupportedHost(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux runs the data plane (the lab tests `thinkpol up` there)")
	}
	for _, node := range []string{"server-1", "device-a"} {
		state, keys := m0State(t, node)
		code, stdout, stderr := runCLI(t, "up", "-state", state)
		if code != 1 || !strings.Contains(stderr, "no data plane on "+runtime.GOOS) {
			t.Fatalf("%s: exit %d, stdout %q, stderr %q", node, code, stdout, stderr)
		}
		noSecrets(t, keys, stdout+stderr)
	}
}

// noSecrets fails if out holds any private key of the key directory.
func noSecrets(t *testing.T, keys, out string) {
	t.Helper()
	for _, name := range []string{"server-1", "device-a", "device-b"} {
		k, err := devmap.ReadNodeKey(filepath.Join(keys, name+".key"))
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range [][]byte{k.Map[:], k.WireGuard[:]} {
			if strings.Contains(out, hex.EncodeToString(secret)) {
				t.Fatalf("%s's private key in the output", name)
			}
		}
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
