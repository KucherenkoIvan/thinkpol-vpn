package agent

import (
	"bytes"
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
	return Config{StateDir: dir, Mode: ModeAuto, LogLevel: "info", Interface: "thinkpol0", LinkMTU: 1500, MapPoll: time.Second}
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
	vars := []string{"THINKPOL_STATE_DIR", "THINKPOL_MAP", "THINKPOL_MODE", "THINKPOL_LOG_LEVEL", "THINKPOL_INTERFACE", "THINKPOL_LINK_MTU", "THINKPOL_MAP_POLL"}
	for _, k := range vars {
		if v, ok := os.LookupEnv(k); ok {
			t.Cleanup(func() { _ = os.Setenv(k, v) })
			_ = os.Unsetenv(k)
		}
	}
	cfg, err := LoadConfig()
	if err != nil {
		t.Fatal(err)
	}
	want := Config{StateDir: DefaultStateDir, Mode: ModeAuto, LogLevel: "info", MapPoll: 5 * time.Second}
	if cfg != want || cfg.MapPath() != filepath.Join(DefaultStateDir, MapFileName) {
		t.Fatalf("defaults %+v", cfg)
	}
	if err := cfg.Check(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("THINKPOL_MODE", "device")
	t.Setenv("THINKPOL_MAP", "/x/m.bin")
	t.Setenv("THINKPOL_MAP_POLL", "2s")
	if cfg, err = LoadConfig(); err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != ModeDevice || cfg.MapPath() != "/x/m.bin" || cfg.MapPoll != 2*time.Second {
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
