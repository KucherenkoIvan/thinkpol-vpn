package agent

import (
	"bytes"
	"context"
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
	return Config{StateDir: dir, Mode: ModeAuto, LogLevel: "info", Interface: "thinkpol0", LinkMTU: 1500, MapPoll: time.Second,
		Connect: true, APISocket: "/run/thinkpol-api/api.sock"}
}

func TestPrepareTakesTheModeFromTheNodesKind(t *testing.T) {
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
		{s.a, ModeAuto, ModeServer},
		{s.b, ModeAuto, ModeDevice},
		{s.a, ModeDevice, ModeDevice},
		{s.b, ModeServer, ModeServer},
	} {
		cfg := testConfig(s.stateDir(t, tc.keys, 1))
		cfg.Mode = tc.mode
		n, err := Prepare(cfg, logs)
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
		if _, err := Prepare(cfg, Logs{}); err == nil || !strings.Contains(err.Error(), tc.want) {
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
	want := Config{Mode: ModeAuto, LogLevel: "info", MapPoll: 5 * time.Second, Connect: true, APIGroup: "thinkpol", DNS: true}
	if cfg != want {
		t.Fatalf("defaults %+v", cfg)
	}
	t.Setenv("THINKPOL_MODE", "device")
	t.Setenv("THINKPOL_MAP", "/x/m.bin")
	t.Setenv("THINKPOL_MAP_POLL", "2s")
	t.Setenv("THINKPOL_CONNECT", "false")
	if cfg, err = LoadConfig(); err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeDevice || cfg.MapPath() != "/x/m.bin" || cfg.MapPoll != 2*time.Second || cfg.Connect {
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
	n, err := Prepare(testConfig(dir), logs)
	if err != nil {
		t.Fatal(err)
	}
	if !n.State().Removed || n.Mode() != ModeAuto {
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
	if !strings.Contains(out.String(), "removed from space") || !strings.Contains(out.String(), "back in space") {
		t.Fatalf("log:\n%s", out.String())
	}

	// Stopping while waiting is a clean stop.
	n.state.Removed = true
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if n.awaitSection(ctx, maps) {
		t.Fatal("went on after the stop")
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
