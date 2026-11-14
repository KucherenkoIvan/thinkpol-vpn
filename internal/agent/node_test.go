package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

func testConfig(dir string) Config {
	return Config{StateDir: dir, Mode: ModeDevice, LogLevel: "info", Interface: "thinkpol0", LinkMTU: 1500, MapPoll: time.Second,
		Connect: true, APISocket: "/run/thinkpol-api/api.sock"}
}

// serverConfig is testConfig for a server: a's section runs in server
// mode only when told to.
func serverConfig(dir string) Config {
	c := testConfig(dir)
	c.Mode = ModeServer
	return c
}

// The service is installed for the node file's mode; a node file that
// sets none leaves the node a device, installed as one only while its map
// shows it as one: one the map makes a server or doesn't hold is
// installed for a server, which keeps no crash trace, with why. A state
// directory the node can't run from, or a node file asking for the gone
// auto, is an error. Crash tracing (knownDevice) follows the same rule.
func TestServiceModeIsTheNodesMode(t *testing.T) {
	s := newTestSpace(t)
	withMode := func(dir, mode string) string {
		writeFile(t, filepath.Join(dir, NodeFile), []byte(`{"mode": "`+mode+`"}`), 0o600)
		return dir
	}
	removed := func(dir string, k NodeKeys) string {
		writeFile(t, filepath.Join(dir, MapFileName), s.buildWithout(t, 1, k), 0o644)
		return dir
	}
	for name, tc := range map[string]struct {
		dir  string
		mode Mode
		why  ModeUnknown
	}{
		"a server set to server":        {withMode(s.stateDir(t, s.a, 1), "server"), ModeServer, ModeKnown},
		"a server, no mode":             {s.stateDir(t, s.a, 1), ModeServer, UnknownMapShowsServer},
		"a device, no mode":             {s.stateDir(t, s.b, 1), ModeDevice, ModeKnown},
		"a server set to device":        {withMode(s.stateDir(t, s.a, 1), "device"), ModeDevice, ModeKnown},
		"a device set to server":        {withMode(s.stateDir(t, s.b, 1), "server"), ModeServer, ModeKnown},
		"a device missing from the map": {removed(s.stateDir(t, s.b, 1), s.b), ModeServer, UnknownNotInMap},
		"one missing, set to device":    {withMode(removed(s.stateDir(t, s.b, 1), s.b), "device"), ModeDevice, ModeKnown},
	} {
		mode, why, err := ServiceMode(tc.dir)
		if err != nil || mode != tc.mode || why != tc.why {
			t.Errorf("%s: %q, why %d, %v", name, mode, why, err)
		}
		if device := tc.mode == ModeDevice && tc.why == ModeKnown; knownDevice(tc.dir) != device {
			t.Errorf("%s: known to be a device %v", name, !device)
		}
	}
	empty := filepath.Join(tempDir(t), "state")
	if err := os.Mkdir(empty, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ServiceMode(empty); err == nil {
		t.Error("a node without keys can run")
	}
	var cerr *ConfigError
	if _, _, err := ServiceMode(withMode(s.stateDir(t, s.a, 1), "auto")); !errors.As(err, &cerr) || !strings.Contains(err.Error(), "gone") {
		t.Errorf("a node file asking for auto: %v", err)
	}
}

// The mode is the node's own: its kind in the map never picks it.
func TestTheModeIsTheNodesNotTheMaps(t *testing.T) {
	s := newTestSpace(t)
	var out bytes.Buffer
	logs, err := NewLogs("info", &out)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		keys NodeKeys
		mode Mode
		want Mode
	}{
		{s.a, ModeDevice, ModeDevice},
		{s.b, ModeDevice, ModeDevice},
		{s.a, ModeServer, ModeServer},
		{s.b, ModeServer, ModeServer},
	} {
		cfg := testConfig(s.stateDir(t, tc.keys, 1))
		cfg.Mode = tc.mode
		n, err := Prepare(cfg, logs, testPlatform())
		if err != nil {
			t.Fatal(err)
		}
		if n.Mode() != tc.want {
			t.Errorf("node %v in mode %s runs as %s, want %s", tc.keys.ID, tc.mode, n.Mode(), tc.want)
		}
	}
}

func TestPrepareChecksTheConfig(t *testing.T) {
	s := newTestSpace(t)
	dir := s.stateDir(t, s.b, 1)
	for _, tc := range []struct {
		change func(*Config)
		want   string
	}{
		{func(c *Config) { c.Mode = "client" }, `mode "client"`},
		{func(c *Config) { c.Mode = "auto" }, `mode "auto" is gone`},
		{func(c *Config) { c.LogLevel = "loud" }, `log level "loud"`},
		{func(c *Config) { c.Interface = "a/b" }, `interface name "a/b"`},
		{func(c *Config) { c.Interface = "much-too-long-name" }, "1 to 15"},
		{func(c *Config) { c.LinkMTU = 100 }, "link MTU 100"},
		{func(c *Config) { c.MapPoll = 0 }, "map poll interval"},
		{func(c *Config) { c.StateDir = "" }, "no state directory"},
		{func(c *Config) { c.APISocket = "api.sock" }, "absolute path"},
		{func(c *Config) { c.MapFile = filepath.Join(dir, "none") }, "none"},
	} {
		cfg := testConfig(dir)
		tc.change(&cfg)
		if _, err := Prepare(cfg, Logs{}, testPlatform()); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("got %v, want an error with %q", err, tc.want)
		}
	}
}

func TestLoadConfig(t *testing.T) {
	for _, kv := range os.Environ() {
		if k, _, _ := strings.Cut(kv, "="); strings.HasPrefix(k, "THINKPOL_") {
			t.Setenv(k, "")
			_ = os.Unsetenv(k)
		}
	}
	// StateDir and APISocket stay empty: the platform defaults are not the load's.
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	want := Config{Mode: ModeDevice, LogLevel: "info", MapPoll: 5 * time.Second, Connect: true, APIGroup: "thinkpol", DNS: true, FailClosedAfterCrash: true}
	if cfg != want {
		t.Fatalf("defaults %+v", cfg)
	}
	t.Setenv("THINKPOL_MODE", "server")
	t.Setenv("THINKPOL_MAP", "/x/m.bin")
	t.Setenv("THINKPOL_MAP_POLL", "2s")
	t.Setenv("THINKPOL_CONNECT", "false")
	if cfg, err = LoadConfig(); err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeServer || cfg.MapPath() != "/x/m.bin" || cfg.MapPoll != 2*time.Second || cfg.Connect {
		t.Fatalf("from the environment %+v", cfg)
	}
}

func TestWorkerOutputKeepsLinesWhole(t *testing.T) {
	var buf bytes.Buffer
	o := &workerOutput{w: &buf}
	a, b := o.forSpace(netmap.SpaceID{1}), o.forSpace(netmap.SpaceID{2})
	var wg sync.WaitGroup
	for i, w := range []interface{ Write([]byte) (int, error) }{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range 100 {
				// Each line in two writes.
				_, _ = fmt.Fprintf(w, "line %d", j)
				_, _ = fmt.Fprintf(w, " of %d\n", i)
			}
		}()
	}
	wg.Wait()
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 200 {
		t.Fatalf("%d lines", len(lines))
	}
	for _, l := range lines {
		ok := strings.HasPrefix(l, "worker space="+netmap.SpaceID{1}.String()+" line ") && strings.HasSuffix(l, " of 0") ||
			strings.HasPrefix(l, "worker space="+netmap.SpaceID{2}.String()+" line ") && strings.HasSuffix(l, " of 1")
		if !ok {
			t.Fatalf("mixed line %q", l)
		}
	}
}

// A node whose map, valid, has no section for it (it was removed while it
// was down) starts idle and runs once a map includes it again.
func TestARemovedNodeWaitsForAMapWithIt(t *testing.T) {
	s := newTestSpace(t)
	dir := s.stateDir(t, s.b, 1)
	writeFile(t, filepath.Join(dir, MapFileName), s.buildWithout(t, 1, s.b), 0o644)
	var out bytes.Buffer
	logs, err := NewLogs("info", &out)
	if err != nil {
		t.Fatal(err)
	}
	n, err := Prepare(testConfig(dir), logs, testPlatform())
	if err != nil {
		t.Fatal(err)
	}
	if !n.State().Removed || n.Mode() != ModeDevice {
		t.Fatalf("removed %v, mode %s", n.State().Removed, n.Mode())
	}

	maps := make(chan []byte, 1)
	result := make(chan bool, 1)
	go func() { result <- n.awaitSection(context.Background(), maps) }()
	maps <- s.buildWithout(t, 1, s.b) // not newer
	maps <- s.buildWithout(t, 2, s.b) // newer, still without it
	maps <- s.build(t, 2)             // not newer than what it took
	maps <- s.build(t, 3)
	select {
	case ok := <-result:
		if !ok {
			t.Fatal("gave up")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("still waiting:\n%s", out.String())
	}
	if st := n.State(); st.Removed || st.Map.Header().Version != 3 || st.Section.Node.ID != s.b.ID || n.Mode() != ModeDevice {
		t.Fatalf("removed %v, version %d, section of %v, mode %s", st.Removed, st.Map.Header().Version, st.Section.Node.ID, n.Mode())
	}
	// One back-in-space line, saying which mode the node came back as.
	if got := out.String(); !strings.Contains(got, "removed from space") ||
		strings.Count(got, "back in space") != 1 || !strings.Contains(got, "version=3 mode=device") {
		t.Fatalf("log:\n%s", got)
	}

	// Stopping while waiting is a clean stop.
	n.state.Removed = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n.awaitSection(ctx, maps) {
		t.Fatal("went on after the stop")
	}
}

// A device waiting for a map with it takes a preset as it waits: stored
// and shown, for the data plane that runs once a map has it.
func TestARemovedDeviceTakesARulePreset(t *testing.T) {
	s := newTestSpace(t)
	dir := s.stateDir(t, s.b, 1)
	writeFile(t, filepath.Join(dir, MapFileName), s.buildWithout(t, 1, s.b), 0o644)
	n, err := Prepare(testConfig(dir), Logs{}, testPlatform())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	maps := make(chan []byte, 1)
	result := make(chan bool, 1)
	go func() { result <- n.awaitSection(ctx, maps) }()
	if err := n.SetRulePreset(ctx, "all-but-domestic"); err != nil {
		t.Fatal(err)
	}
	wantPreset(t, n, "all-but-domestic")
	maps <- s.build(t, 2)
	if !<-result {
		t.Fatal("gave up")
	}
	n.settingsMu.Lock()
	defer n.settingsMu.Unlock()
	if p := n.device.Rules.Preset.String(); p != "all-but-domestic" {
		t.Fatalf("the data plane starts with %q", p)
	}
}

// A server removed while it was down is a server all the same: it
// refuses a connect at once, its mode known before a map has it, and its
// one back-in-space line has its mode.
func TestARemovedServerRefusesConnect(t *testing.T) {
	s := newTestSpace(t)
	dir := s.stateDir(t, s.a, 1)
	writeFile(t, filepath.Join(dir, MapFileName), s.buildWithout(t, 1, s.a), 0o644)
	var out bytes.Buffer
	logs, err := NewLogs("info", &out)
	if err != nil {
		t.Fatal(err)
	}
	n, err := Prepare(serverConfig(dir), logs, testPlatform())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	maps := make(chan []byte, 1)
	result := make(chan bool, 1)
	go func() { result <- n.awaitSection(ctx, maps) }()
	if err := n.Connect(ctx); !errors.Is(err, ErrServerMode) {
		t.Fatalf("got %v, want ErrServerMode", err)
	}
	if st := n.Status(); !st.Removed || st.Mode != ModeServer {
		t.Fatalf("status %+v", st)
	}
	maps <- s.build(t, 2)
	if !<-result {
		t.Fatalf("gave up:\n%s", out.String())
	}
	if got := out.String(); strings.Count(got, "back in space") != 1 || !strings.Contains(got, "version=2 mode=server") {
		t.Fatalf("log:\n%s", got)
	}
}

func TestSanitizeDisarmsTerminalControls(t *testing.T) {
	for in, want := range map[string]string{
		"plain text, tabs\tand ünïcode": "plain text, tabs\tand ünïcode",
		"\x1b[2J\x1b]0;title\x07":       `\x1b[2J\x1b]0;title\x07`,
		"line\nbreak\r":                 `line\x0abreak\x0d`,
		"del\x7f bad\xff":               `del\x7f bad\xff`,
		"c1 \u009b bidi \u202e x":       `c1 \u009b bidi \u202e x`,
	} {
		if got := Sanitize(in); got != want {
			t.Errorf("Sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
