package main

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

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
// runs each node in its own mode: with no -mode and no node file
// setting, a device, even the node the map makes a server; -mode server,
// THINKPOL_MODE or the node file's "mode" run it as a server.
func TestUpRunsANodeAsADeviceUnlessToldOtherwise(t *testing.T) {
	for _, tc := range []struct {
		name, node, file string
		env, args        []string
		want             agent.Mode
	}{
		{"a server, no mode", "server-1", "", nil, nil, agent.ModeDevice},
		{"a device, no mode", "device-a", "", nil, nil, agent.ModeDevice},
		{"a server by its node file", "server-1", `{"mode": "server"}`, nil, nil, agent.ModeServer},
		{"a server by the environment", "server-1", "", []string{"THINKPOL_MODE", "server"}, nil, agent.ModeServer},
		{"a server by its flag", "server-1", "", nil, []string{"-mode", "server"}, agent.ModeServer},
		{"a flag over the node file", "server-1", `{"mode": "server"}`, nil, []string{"-mode", "device"}, agent.ModeDevice},
		{"a flag over the environment", "server-1", "", []string{"THINKPOL_MODE", "server"}, []string{"-mode", "device"}, agent.ModeDevice},
		{"the environment over the node file", "server-1", `{"mode": "device"}`, []string{"THINKPOL_MODE", "server"}, nil, agent.ModeServer},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unsetTHINKPOL(t)
			state, _ := m0State(t, tc.node)
			if tc.file != "" {
				if err := os.WriteFile(filepath.Join(state, agent.NodeFile), []byte(tc.file), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if tc.env != nil {
				t.Setenv(tc.env[0], tc.env[1])
			}
			cfg, err := upConfig(env{}, append([]string{"-state", state, "-api-socket", ""}, tc.args...))
			if err != nil {
				t.Fatal(err)
			}
			n, err := agent.Prepare(cfg, agent.Logs{}, platform())
			if err != nil {
				t.Fatal(err)
			}
			if n.Mode() != tc.want {
				t.Errorf("runs in %s mode, want %s", n.Mode(), tc.want)
			}
		})
	}
}

// A mode up can't run with exits EX_CONFIG, auto among them: it is gone.
func TestUpRefusesABadMode(t *testing.T) {
	unsetTHINKPOL(t)
	state, _ := m0State(t, "server-1")
	for _, args := range [][]string{{"-mode", "auto"}, {"-mode", "client"}} {
		code, _, stderr := runCLI(t, append([]string{"up", "-state", state}, args...)...)
		if code != exitConfig || strings.Contains(stderr, "gone") != (args[1] == "auto") {
			t.Errorf("%v: exit %d: %s", args, code, stderr)
		}
	}
	t.Setenv("THINKPOL_MODE", "auto")
	if code, _, stderr := runCLI(t, "up", "-state", state); code != exitConfig || !strings.Contains(stderr, `mode "auto" is gone`) {
		t.Errorf("THINKPOL_MODE=auto: exit %d: %s", code, stderr)
	}
	unsetTHINKPOL(t)
	if err := os.WriteFile(filepath.Join(state, agent.NodeFile), []byte(`{"mode": "auto"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := runCLI(t, "up", "-state", state); code != exitConfig || !strings.Contains(stderr, "gone") {
		t.Errorf("a node file asking for auto: exit %d: %s", code, stderr)
	}
}

// unsetTHINKPOL hides the developer's exported THINKPOL_ variables from
// the test and the commands it runs: t.Setenv restores each one's old
// value at cleanup, set or unset as it was.
func unsetTHINKPOL(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		k, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(k, "THINKPOL_") {
			t.Setenv(k, "")
			_ = os.Unsetenv(k)
		}
	}
}

// The platform defaults for what the environment left unset: the state
// directory and the API socket of this OS, validated with the rest; a
// set-empty socket stays (it means no local API), and an environment-set
// state directory stays.
func TestUpAppliesThePlatformDefaults(t *testing.T) {
	unsetTHINKPOL(t)
	cfg, err := agent.LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	agent.ApplyOSDefaults(&cfg)
	want := agent.Config{StateDir: agent.DefaultStateDir, Mode: agent.ModeDevice, LogLevel: "info", MapPoll: 5 * time.Second,
		Connect: true, APISocket: agent.DefaultAPISocket(), APIGroup: "thinkpol", DNS: true}
	if cfg != want {
		t.Fatalf("defaults %+v", cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("THINKPOL_API_SOCKET", "")
	if cfg, err = agent.LoadConfig(); err != nil {
		t.Fatal(err)
	}
	agent.ApplyOSDefaults(&cfg)
	if cfg.APISocket != "" || cfg.StateDir != agent.DefaultStateDir {
		t.Fatalf("a set-empty socket must stay: %+v", cfg)
	}
	t.Setenv("THINKPOL_API_SOCKET", "")
	_ = os.Unsetenv("THINKPOL_API_SOCKET")
	envState := filepath.Join(tempDir(t), "env-state")
	t.Setenv("THINKPOL_STATE_DIR", envState)
	if cfg, err = agent.LoadConfig(); err != nil {
		t.Fatal(err)
	}
	agent.ApplyOSDefaults(&cfg)
	if cfg.StateDir != envState || cfg.APISocket != agent.DefaultAPISocket() {
		t.Fatalf("an environment-set state directory must stay: got %q, want %q", cfg.StateDir, envState)
	}
}

func TestUpRefusesAnInvalidMap(t *testing.T) {
	unsetTHINKPOL(t)
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
	unsetTHINKPOL(t)
	if runtime.GOOS == "linux" {
		t.Skip("Linux runs the data plane (the lab tests `thinkpol up` there)")
	}
	nodes, refusal := []string{"server-1", "device-a"}, "no data plane on "+runtime.GOOS
	if runtime.GOOS == "darwin" {
		// A device runs on macOS (as root, on the real network: never
		// here); a server refuses before touching anything.
		nodes, refusal = []string{"server-1"}, "server mode needs Linux"
	}
	for _, node := range nodes {
		state, keys := m0State(t, node)
		args := []string{"up", "-state", state}
		if node == "server-1" {
			// Without it, a device: one that would run here.
			args = append(args, "-mode", "server")
		}
		code, stdout, stderr := runCLI(t, args...)
		if code != 1 || !strings.Contains(stderr, refusal) {
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

// up's flags are agent.Config's tags: the help names each one's variable,
// and a flag overrides its variable before the configuration is validated.
func TestUpFlagsOverrideTheEnvironment(t *testing.T) {
	unsetTHINKPOL(t)
	code, _, stderr := runCLI(t, "up", "-h")
	for _, want := range []string{"-state", "(env THINKPOL_STATE_DIR)", "-log-level", "(env THINKPOL_LOG_LEVEL)", "-dns-upstream"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("exit %d, help misses %q:\n%s", code, want, stderr)
		}
	}

	state, _ := m0State(t, "device-a")
	path := filepath.Join(state, agent.MapFileName)
	env := readTestFile(t, path)
	env[len(env)/2] ^= 1 // stops `up` right after validation, before any data plane
	if err := os.WriteFile(path, env, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("THINKPOL_LINK_MTU", "100")
	if code, _, stderr := runCLI(t, "up", "-state", state); code != exitConfig || !strings.Contains(stderr, "link MTU 100") {
		t.Fatalf("an invalid variable must fail validation: exit %d, stderr %q", code, stderr)
	}
	if code, _, stderr := runCLI(t, "up", "-state", state, "-link-mtu", "1500"); code != 1 || !strings.Contains(stderr, "is not a valid map") {
		t.Fatalf("the flag must override the variable before validation: exit %d, stderr %q", code, stderr)
	}
}

// A node file `up` can't take stops it with EX_CONFIG (78), naming the
// file and the key or the value. A flag that sets the same key doesn't
// hide the mistake: the file is the operator's, and wrong.
func TestUpRefusesABadNodeFile(t *testing.T) {
	unsetTHINKPOL(t)
	state, _ := m0State(t, "device-a")
	for name, tc := range map[string]struct {
		file string
		args []string
		want string
	}{
		"unknown key":                {`{"link_mut": 1400}`, nil, `unknown key "link_mut"`},
		"bad value":                  {`{"link_mtu": 100}`, nil, `key "link_mtu": link MTU 100`},
		"bad value, flag set":        {`{"link_mtu": 100}`, []string{"-link-mtu", "1400"}, `key "link_mtu": link MTU 100`},
		"bad mode":                   {`{"mode": "exit"}`, nil, `key "mode": mode "exit"`},
		"wrong type":                 {`{"dns": "yes"}`, nil, `key "dns": want true or false, not string`},
		"duplicate key":              {`{"mode": "device", "mode": "server"}`, nil, `key "mode" given twice`},
		"invalid JSON":               {`{"mode": "device",}`, nil, "invalid JSON"},
		"an upstream that isn't one": {`{"dns_upstream": ["192.0.2.53:0"]}`, nil, `key "dns_upstream": DNS upstream "192.0.2.53:0"`},
	} {
		if err := os.WriteFile(filepath.Join(state, agent.NodeFile), []byte(tc.file), 0o600); err != nil {
			t.Fatal(err)
		}
		code, _, stderr := runCLI(t, append([]string{"up", "-state", state}, tc.args...)...)
		if code != exitConfig || !strings.Contains(stderr, tc.want) || !strings.Contains(stderr, filepath.Join(state, agent.NodeFile)) {
			t.Errorf("%s: exit %d, stderr %q", name, code, stderr)
		}
	}
}

// A bad environment, or a configuration only Prepare can tell is bad,
// exits 78 as a bad node file does; so does the variable only an older
// service definition sets, which would have the node connect at every
// start.
func TestUpRefusesABadEnvironment(t *testing.T) {
	unsetTHINKPOL(t)
	state, _ := m0State(t, "device-a")
	for name, tc := range map[string]struct {
		env  map[string]string
		args []string
		want string
	}{
		// The relative socket stops `up` short of running on this host
		// should the check ever be lost.
		"an older service definition":                 {map[string]string{"THINKPOL_CONNECT_ON_BOOT": "off"}, []string{"-api-socket", "api.sock"}, "thinkpol service install"},
		"an MTU that isn't a number":                  {map[string]string{"THINKPOL_LINK_MTU": "abc"}, nil, "abc"},
		"an MTU out of range":                         {map[string]string{"THINKPOL_LINK_MTU": "100"}, nil, "link MTU 100"},
		"a bool that isn't one":                       {map[string]string{"THINKPOL_DNS": "yes"}, nil, "yes"},
		"a device disconnected without the local API": {nil, []string{"-connect=false", "-api-socket", ""}, "needs the local API"},
	} {
		t.Run(name, func(t *testing.T) {
			for k, v := range tc.env {
				t.Setenv(k, v)
			}
			code, _, stderr := runCLI(t, append([]string{"up", "-state", state}, tc.args...)...)
			if code != exitConfig || !strings.Contains(stderr, tc.want) {
				t.Errorf("exit %d, stderr %q", code, stderr)
			}
		})
	}
}
