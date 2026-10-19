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
// (PRD C4, success metric 1) and regenerates lab/RESULTS.md. Every cell is
// probed in its own lab, and a transport's censored cells run in parallel:
// a transport passes when its
// data crossed the censor in the lab router over IPv4 and over IPv6, and
// fails when it crossed over neither. A cell whose outcome contradicts what
// its censor means to produce fails the test, and a cell whose censor can't
// be trusted (censord died, the kernel dropped queued packets, the verdict
// log doesn't show the probe's flows) is an error. RESULTS.md is written
// only by a complete run with no error.
//
// A transport's off cell (no censor) runs before its censored cells and
// they read its result: against a censor it must still pass what it passed
// without one. A censored cell without a passing off cell is an error and
// fails fast, whether the off cell didn't run (a -run filter can select the
// cell alone) or it failed. Every cell holds its own lab slot
// (lab.StartOwnSlot: one per subtest).
func TestCensorMatrix(t *testing.T) {
	t.Parallel()
	var (
		mu    sync.Mutex
		cells []matrixCell
	)
	record := func(cell matrixCell) {
		mu.Lock()
		defer mu.Unlock()
		cells = append(cells, cell)
	}
	t.Cleanup(func() { writeResults(t, cells, len(transports)*len(censorCases)) })

	// runCell probes one cell and records it: t.Fatal below ends the
	// function before its return, the deferred record is what survives.
	runCell := func(t *testing.T, tr transport, cc censorCase) matrixCell {
		cell := matrixCell{transport: tr.name, censor: cc.name, result: "error"}
		defer func() { record(cell) }()

		l := lab.StartOwnSlot(t, lab.Standard())
		target, err := tr.setup(t, l)
		if err != nil {
			cell.detail = "setup failed"
			t.Fatal(err)
		}
		var c *censorRun
		if cc.modules != nil {
			c = startCensor(t, l, cc.modules(t, l))
		}

		want := cc.want(tr.name)
		crossed := tr.probe(t, l, target, want == "pass")
		cell.result, cell.detail = score(crossed)

		if c != nil {
			if err := c.healthy(t); err != nil {
				cell.result, cell.detail = "error", "censor unhealthy"
				t.Fatal(err)
			}
			if err := tr.sawFlows(t, l, c); err != nil {
				cell.result, cell.detail = "error", "the verdict log misses the probe's flows"
				t.Fatal(err)
			}
		}
		if want == "fail" {
			how, err := blockedBy(t, l, c)
			if err != nil {
				t.Error(err)
			} else if cell.result == "fail" {
				cell.detail += "; the censor " + how + " them"
			}
		}
		if cell.result != want {
			t.Errorf("%s against %s: %s (%s), want %s", tr.name, cc.name, cell.result, cell.detail, want)
		}
		return cell
	}

	off, censored := censorCases[0], censorCases[1:]
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			t.Parallel()
			offResult := "" // the off cell's result; "" when it didn't run
			t.Run("off", func(t *testing.T) {
				// runCell records the cell even when t.Fatal stops it,
				// but the assignment would not happen: claim that the
				// cell ran before it can fail.
				offResult = "error"
				offResult = runCell(t, tr, off).result
			})
			for _, cc := range censored {
				if cc.modules == nil {
					continue
				}
				t.Run(cc.name, func(t *testing.T) {
					t.Parallel()
					if offResult == "" {
						record(matrixCell{transport: tr.name, censor: cc.name,
							result: "error", detail: "the off cell didn't run"})
						t.Fatalf("%s without a censor: the off cell didn't run", tr.name)
					}
					if offResult != "pass" {
						record(matrixCell{transport: tr.name, censor: cc.name,
							result: "error", detail: "the transport failed without a censor"})
						t.Fatalf("the transport failed without a censor: %s can't be judged", cc.name)
					}
					runCell(t, tr, cc)
				})
			}
		})
	}
}

type matrixCell struct {
	transport, censor, result, detail string
}

// crossed is what a probe found: whether data crossed over each family.
type crossed struct{ v4, v6 bool }

func score(c crossed) (result, detail string) {
	switch {
	case c.v4 && c.v6:
		return "pass", ""
	case c.v4:
		return "fail", "only IPv4 crossed"
	case c.v6:
		return "fail", "only IPv6 crossed"
	}
	return "fail", "neither IPv4 nor IPv6 crossed"
}

type censorCase struct {
	name string
	// expect is each transport's result when the censor works as meant;
	// a transport not in it must pass.
	expect  map[string]string
	modules func(t *testing.T, l *lab.Lab) []censor.ModuleConfig // nil: no censord
}

func (cc censorCase) want(transport string) string {
	if w, ok := cc.expect[transport]; ok {
		return w
	}
	return "pass"
}

// Row names. The plain-tcp row is no transport: it is the control that TCP
// on the underlay, what a TLS-shaped transport rides, crosses the censor.
const (
	rowUDP      = "udp"
	rowPlainTCP = "plain-tcp (control)"
)

var censorCases = []censorCase{
	{name: "off"},
	{name: "block-ip (elsewhere)", modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
		return []censor.ModuleConfig{{Name: "block-ip", Settings: json.RawMessage(
			`{"destinations": ["203.0.113.9", "2001:db8::9"]}`)}}
	}},
	{name: "block-ip (entry)", expect: map[string]string{rowUDP: "fail", rowPlainTCP: "fail"},
		modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig { return entryBlockSettings(t, l, "drop") }},
	// Reset is TCP's; on udp the engine drops instead.
	{name: "block-ip reset (entry)", expect: map[string]string{rowUDP: "fail", rowPlainTCP: "fail"},
		modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig { return entryBlockSettings(t, l, "reset") }},
}

// probeTarget is what a probe sends to: overlay addresses for a transport,
// server-1's own for the control.
type probeTarget struct{ v4, v6 netip.Addr }

type transport struct {
	name  string
	setup func(t *testing.T, l *lab.Lab) (probeTarget, error)
	// probe reports whether data crossed over each family; wantPass gives
	// it time to retry, otherwise it settles a blocked family quickly.
	probe func(t *testing.T, l *lab.Lab, to probeTarget, wantPass bool) crossed
	// sawFlows checks the verdict log has the probe's flows on the
	// underlay: the censor saw what it judged.
	sawFlows func(t *testing.T, l *lab.Lab, c *censorRun) error
}

var transports = []transport{
	{rowPlainTCP, setupPlainTCP, probePlainTCP, sawPlainTCP},
	{rowUDP, setupUDP, probeUDP, sawUDP},
}

// probeWindow is how long a probe retries a family that should cross; one
// that should not gets blockedWindow.
const probeWindow, blockedWindow = 30 * time.Second, 8 * time.Second

func window(wantPass bool) time.Duration {
	if wantPass {
		return probeWindow
	}
	return blockedWindow
}

func setupPlainTCP(t *testing.T, l *lab.Lab) (probeTarget, error) {
	server := l.Node(lab.Server1)
	listenTCP(t, server)
	return probeTarget{server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)}, nil
}

func probePlainTCP(t *testing.T, l *lab.Lab, to probeTarget, wantPass bool) crossed {
	dev := l.Node(lab.DeviceA)
	return crossed{
		v4: tcpCrosses(dev, to.v4, window(wantPass)) == nil,
		v6: tcpCrosses(dev, to.v6, window(wantPass)) == nil,
	}
}

func sawPlainTCP(t *testing.T, l *lab.Lab, c *censorRun) error {
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	for _, src := range []netip.Addr{dev.IPv4(lab.NetDevices), dev.IPv6(lab.NetDevices)} {
		dst := serverAddrFor(server, src)
		if !c.logged(t, func(e verdictLine) bool {
			return e.Key.Proto == censor.ProtoTCP && e.Key.Src == src && e.Key.Dst == dst && e.Key.DstPort == tcpProbePort
		}) {
			return fmt.Errorf("no TCP flow %s -> %s:%d in the verdict log", src, dst, tcpProbePort)
		}
	}
	return nil
}

func setupUDP(t *testing.T, l *lab.Lab) (probeTarget, error) {
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	space := newM0Space(t, l.Node(lab.Internet), server)
	envelope, version := space.build(t)
	space.install(t, dev, "device-a", envelope)
	space.install(t, server, "server-1", envelope)
	upDev := dev.Start(t, "thinkpol", "up")
	upSrv := server.Start(t, "thinkpol", "up")
	applied := applied(version)
	if err := waitOutput(upSrv, applied, 60*time.Second); err != nil {
		return probeTarget{}, fmt.Errorf("server-1: %w", err)
	}
	if err := waitOutput(upDev, applied, 60*time.Second); err != nil {
		return probeTarget{}, fmt.Errorf("device-a: %w", err)
	}
	if err := waitOutput(upDev, `link up`, 60*time.Second); err != nil {
		return probeTarget{}, err
	}
	o4, o6 := space.overlay(1)
	return probeTarget{o4, o6}, nil
}

// probeUDP pings server-1's overlay addresses, IPv4 and IPv6, through the
// tunnel.
func probeUDP(t *testing.T, l *lab.Lab, to probeTarget, wantPass bool) crossed {
	dev := l.Node(lab.DeviceA)
	return crossed{
		v4: pingErr(dev, to.v4, window(wantPass)) == nil,
		v6: pingErr(dev, to.v6, window(wantPass)) == nil,
	}
}

// sawUDP: the tunnel runs over one underlay family (m0.yaml's first
// endpoint), so the log needs UDP from device-a to server-1 in either.
func sawUDP(t *testing.T, l *lab.Lab, c *censorRun) error {
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	if !c.logged(t, func(e verdictLine) bool {
		return e.Key.Proto == censor.ProtoUDP &&
			(e.Key.Src == dev.IPv4(lab.NetDevices) && e.Key.Dst == server.IPv4(lab.NetServers) ||
				e.Key.Src == dev.IPv6(lab.NetDevices) && e.Key.Dst == server.IPv6(lab.NetServers))
	}) {
		return fmt.Errorf("no UDP flow device-a -> server-1 in the verdict log")
	}
	return nil
}

// blockedBy checks the verdict log blamed block-ip for the blocked cell:
// it dropped or reset packets to server-1. It returns which.
func blockedBy(t *testing.T, l *lab.Lab, c *censorRun) (string, error) {
	if c == nil {
		return "", fmt.Errorf("a blocking cell without a censor")
	}
	server := l.Node(lab.Server1)
	var verdicts []string
	for _, v := range []censor.Verdict{censor.Drop, censor.Reset} {
		if c.logged(t, func(e verdictLine) bool {
			return e.Verdict == v && e.Module == "block-ip" && (e.Key.Dst == server.IPv4(lab.NetServers) || e.Key.Dst == server.IPv6(lab.NetServers))
		}) {
			verdicts = append(verdicts, map[censor.Verdict]string{censor.Drop: "dropped", censor.Reset: "reset"}[v])
		}
	}
	if len(verdicts) == 0 {
		return "", fmt.Errorf("the transport stopped, but the verdict log has no block-ip drop or reset to server-1")
	}
	return strings.Join(verdicts, " and "), nil
}

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

func pingErr(from *lab.Node, to netip.Addr, within time.Duration) error {
	deadline := time.Now().Add(within)
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

const (
	censorQueue   = 100
	censorLogPath = "/run/censor/verdicts.jsonl"
)

// censorRun is censord running in the lab router, with the kernel's queue
// counters from when it became ready.
type censorRun struct {
	router *lab.Node
	proc   *lab.Process
	start  censor.QueueStats
}

func startCensor(t *testing.T, l *lab.Lab, modules []censor.ModuleConfig) *censorRun {
	t.Helper()
	b, err := json.Marshal(censor.Config{Queue: censorQueue, Log: censorLogPath, Modules: modules})
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
	c := &censorRun{router: router, proc: p}
	if c.start, err = c.stats(t); err != nil {
		t.Fatal(err)
	}
	t.Logf("queue %d when censord was ready: %+v", censorQueue, c.start)
	return c
}

func (c *censorRun) stats(t *testing.T) (censor.QueueStats, error) {
	return censor.ParseQueueStats(c.router.MustExec(t, "cat", "/proc/net/netfilter/nfnetlink_queue"), censorQueue)
}

// healthy is nil when censord is still running and the kernel dropped
// nothing on the way to it since it became ready.
func (c *censorRun) healthy(t *testing.T) error {
	select {
	case <-c.proc.Done():
		return fmt.Errorf("censord exited: %v\n%s", c.proc.Err(), c.proc.Output())
	default:
	}
	now, err := c.stats(t)
	if err != nil {
		return err
	}
	if now.QueueDropped > c.start.QueueDropped || now.UserDropped > c.start.UserDropped {
		return fmt.Errorf("the kernel dropped queued packets: queue_dropped %d -> %d, user_dropped %d -> %d",
			c.start.QueueDropped, now.QueueDropped, c.start.UserDropped, now.UserDropped)
	}
	return nil
}

// verdictLine is a verdict log entry with its flow parsed.
type verdictLine struct {
	censor.LogEntry
	Key censor.FlowKey
}

// logged reports whether a verdict log entry matches, waiting briefly for
// the log to catch up.
func (c *censorRun) logged(t *testing.T, match func(verdictLine) bool) bool {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		for _, line := range strings.Split(c.router.MustExec(t, "cat", censorLogPath), "\n") {
			if line == "" {
				continue
			}
			var e verdictLine
			if err := json.Unmarshal([]byte(line), &e.LogEntry); err != nil {
				t.Fatalf("verdict log line %q: %v", line, err)
			}
			key, err := censor.ParseFlowKey(e.Flow)
			if err != nil {
				continue // not TCP or UDP
			}
			e.Key = key
			if match(e) {
				return true
			}
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func writeResults(t *testing.T, cells []matrixCell, expected int) {
	t.Helper()
	if len(cells) < expected {
		t.Logf("partial matrix run (%d of %d cells): RESULTS.md not written", len(cells), expected)
		return
	}
	for _, c := range cells {
		if c.result == "error" {
			t.Logf("cell %s / %s errored: RESULTS.md not written", c.transport, c.censor)
			return
		}
	}
	if t.Failed() {
		t.Log("the matrix test failed: RESULTS.md not written")
		return
	}
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
	b.WriteString("Did a transport's data cross the censor in the lab router, device-a to server-1: " +
		"pass when it crossed over IPv4 and over IPv6, fail when it didn't. Every cell is probed. " +
		"`plain-tcp (control)` is not a transport: it shows that plain TCP on the underlay crosses the censor, and that the censor sees it.\n\n")
	b.WriteString("| transport | censor | result | detail |\n|---|---|---|---|\n")
	for _, c := range cells {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.transport, c.censor, c.result, strings.ReplaceAll(c.detail, "|", `\|`))
	}
	if err := os.WriteFile(filepath.Join(root, "lab", "RESULTS.md"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}
