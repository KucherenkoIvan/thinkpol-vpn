//go:build lab

package lab_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/censor"
)

// TestCensorMatrix scores every transport against every censor module
// (PRD C4, success metric 1) and regenerates lab/RESULTS.md. A cell's
// result is whether the transport's data crossed the censor in the lab
// router; a cell whose outcome contradicts what its censor means to
// produce fails the test, not just the matrix.
func TestCensorMatrix(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var results []matrixCell

	for _, tr := range probes {
		for _, cc := range censorCases {
			tr, cc := tr, cc
			t.Run(tr.name+"/"+cc.name, func(t *testing.T) {
				t.Parallel()
				l := lab.Start(t, lab.Standard())
				if cc.modules != nil {
					startCensor(t, l, cc.modules(t, l))
				}
				verdict := "pass"
				if err := tr.run(t, l); err != nil {
					verdict = "fail"
					t.Logf("transport %s against %s: %v", tr.name, cc.name, err)
				}
				if verdict != cc.want {
					t.Errorf("%s against %s: %s, want %s", tr.name, cc.name, verdict, cc.want)
				}
				if cc.name == entryBlockCase && verdict == "fail" {
					// The transport stopping is not enough: the drops
					// must be the censor's, in the verdict log.
					checkDroppedByCensor(t, l)
				}
				mu.Lock()
				defer mu.Unlock()
				results = append(results, matrixCell{tr.name, cc.name, verdict})
			})
		}
	}
	writeResults(t, results)
}

// The censor case that proves the pipeline end to end: the trivial module
// blocking the entry node by destination IP.
const entryBlockCase = "block-ip (entry)"

// matrixCell is one cell of the matrix.
type matrixCell struct{ transport, censor, verdict string }

// censorCase is one column of the matrix: the modules a test starts the
// censor with, and the transport result that means the censor did its
// work.
type censorCase struct {
	name string
	want string // "pass" or "fail"
	// modules builds the config for a lab, whose addresses it needs; nil
	// starts no censor.
	modules func(t *testing.T, l *lab.Lab) []censor.ModuleConfig
}

var censorCases = []censorCase{
	{name: "off", want: "pass"},
	{name: "block-ip (elsewhere)", want: "pass", modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
		return []censor.ModuleConfig{{Name: "block-ip", Settings: json.RawMessage(
			`{"destinations": ["203.0.113.9", "2001:db8::9"]}`)}}
	}},
	{name: entryBlockCase, want: "fail", modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
		server := l.Node(lab.Server1)
		settings, err := json.Marshal(struct {
			Destinations []string `json:"destinations"`
		}{Destinations: []string{
			server.IPv4(lab.NetServers).String(),
			server.IPv6(lab.NetServers).String(),
		}})
		if err != nil {
			t.Fatal(err)
		}
		return []censor.ModuleConfig{{Name: "block-ip", Settings: settings}}
	}},
}

// probes are the transports the matrix scores. Each brings its transport
// up between device-a and server-1, through the router the censor sits in,
// and returns nil when data crossed, both families.
var probes = []struct {
	name string
	run  func(t *testing.T, l *lab.Lab) error
}{
	{"udp", probeUDP},
}

// probeUDP runs the M0 space's udp transport between device-a and
// server-1 and pings across it. Errors are results (a censor's block),
// not failures; a Fatal is broken infrastructure.
func probeUDP(t *testing.T, l *lab.Lab) error {
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	space := newM0Space(t, l.Node(lab.Internet), server) // docker exec only: no routed traffic
	envelope, version := space.build(t)
	space.install(t, dev, "device-a", envelope)
	space.install(t, server, "server-1", envelope)

	upDev := dev.Start(t, "thinkpol", "up")
	upSrv := server.Start(t, "thinkpol", "up")
	applied := applied(version)
	if err := waitOutput(upSrv, applied, 60*time.Second); err != nil {
		return fmt.Errorf("server-1: %w", err)
	}
	if err := waitOutput(upDev, applied, 60*time.Second); err != nil {
		return fmt.Errorf("device-a: %w", err)
	}
	s4, s6 := space.overlay(1)
	if err := pingErr(dev, s4); err != nil {
		return err
	}
	return pingErr(dev, s6)
}

// waitOutput waits for a log line of a started process.
func waitOutput(p *lab.Process, pattern string, timeout time.Duration) error {
	re := regexp.MustCompile(pattern)
	deadline := time.Now().Add(timeout)
	for {
		if re.MatchString(p.Output()) {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("no %q within %s, last output:\n%s", pattern, timeout, p.Output())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// pingErr pings until it works or the timeout passes: an error, for the
// matrix to record.
func pingErr(from *lab.Node, to netip.Addr) error {
	deadline := time.Now().Add(45 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_, err := from.Exec(ctx, "ping", "-c", "1", "-W", "1", to.String())
		cancel()
		if err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("ping %s from %s: %w", to, from.Name, err)
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// startCensor writes the config and starts censord in the router, and
// waits for it to serve the queue.
func startCensor(t *testing.T, l *lab.Lab, modules []censor.ModuleConfig) {
	t.Helper()
	b, err := json.Marshal(censor.Config{
		Queue:   100,
		Log:     "/run/censor/verdicts.jsonl",
		Modules: modules,
	})
	if err != nil {
		t.Fatal(err)
	}
	router := l.Node(lab.Router)
	router.WriteFile(t, "/run/censor/config.json", b)
	p := router.Start(t, "censord", "-config", "/run/censor/config.json")
	lab.Eventually(t, 30*time.Second, func() error {
		if !strings.Contains(p.Output(), "censor ready") {
			return fmt.Errorf("censord not ready yet:\n%s", p.Output())
		}
		return nil
	})
}

// checkDroppedByCensor reads the verdict log and fails the test unless the
// censor dropped traffic to the entry node.
func checkDroppedByCensor(t *testing.T, l *lab.Lab) {
	t.Helper()
	server := l.Node(lab.Server1)
	out := l.Node(lab.Router).MustExec(t, "cat", "/run/censor/verdicts.jsonl")
	drops := 0
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		var e censor.LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("verdict log line %q: %v", line, err)
		}
		for _, a := range []netip.Addr{server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)} {
			if e.Verdict == censor.Drop && strings.Contains(e.Flow, a.String()) {
				drops++
			}
		}
	}
	if drops == 0 {
		t.Errorf("the transport stopped, but the verdict log has no drop for the entry node %s:\n%s",
			server.IPv4(lab.NetServers), out)
		return
	}
	t.Logf("the censor dropped %d packets to the entry node", drops)
}

// writeResults regenerates lab/RESULTS.md from the cells, deterministically
// so a committed file only changes when the matrix does.
func writeResults(t *testing.T, cells []matrixCell) {
	t.Helper()
	root, err := lab.Root()
	if err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(cells, func(a, b matrixCell) int {
		if c := strings.Compare(a.transport, b.transport); c != 0 {
			return c
		}
		return strings.Compare(a.censor, b.censor)
	})
	var b strings.Builder
	b.WriteString("# Censor lab results\n\n")
	b.WriteString("<!-- Generated by `make lab` (TestCensorMatrix); do not edit. -->\n\n")
	b.WriteString("Did a transport's data cross the censor in the lab router: pass when it did, fail when the censor stopped it.\n\n")
	b.WriteString("| transport | censor | result |\n|---|---|---|\n")
	for _, c := range cells {
		fmt.Fprintf(&b, "| %s | %s | %s |\n", c.transport, c.censor, c.verdict)
	}
	if err := os.WriteFile(filepath.Join(root, "lab", "RESULTS.md"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
