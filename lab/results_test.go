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
	"strconv"
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
	var mu sync.Mutex
	var results []matrixCell
	var finished sync.Map // transport/censor -> verdict
	expected := len(probes) * len(censorCases)

	for _, tr := range probes {
		for _, cc := range censorCases {
			tr, cc := tr, cc
			t.Run(tr.name+"/"+cc.name, func(t *testing.T) {
				verdict := "error"
				detail := ""
				defer func() {
					mu.Lock()
					results = append(results, matrixCell{tr.name, cc.name, verdict, detail})
					mu.Unlock()
					finished.Store(tr.name+"/"+cc.name, verdict)
				}()

				if cc.name == entryBlockCase {
					waitOffPass(t, tr.name, &finished)
				}

				l := lab.Start(t, lab.Standard())
				ctx, err := tr.setup(t, l)
				if err != nil {
					detail = err.Error()
					t.Fatal(err)
				}
				var censord *lab.Process
				var qd0, ud0 uint64
				if cc.modules != nil {
					censord, qd0, ud0 = startCensor(t, l, cc.modules(t, l))
				}

				want := cc.want(tr.name)
				probed := true
				if len(cc.expect) > 0 {
					if _, ok := cc.expect[tr.name]; !ok {
						verdict = "pass"
						probed = false
					} else if err := tr.probe(t, l, ctx, cc.tcpMustFail); err != nil {
						verdict = "fail"
						detail = err.Error()
						t.Logf("transport %s against %s: %v", tr.name, cc.name, err)
					} else {
						verdict = "pass"
					}
				} else if err := tr.probe(t, l, ctx, cc.tcpMustFail); err != nil {
					verdict = "fail"
					detail = err.Error()
					t.Logf("transport %s against %s: %v", tr.name, cc.name, err)
				} else {
					verdict = "pass"
				}

				if cc.modules != nil && probed {
					if err := censorHealthSince(t, l, qd0, ud0); err != nil {
						verdict = "error"
						detail = err.Error()
						t.Error(err)
					} else if err := checkVerdictLog(t, l, tr.name); err != nil {
						verdict = "error"
						detail = err.Error()
						t.Error(err)
					}
					if censord != nil && !processAlive(censord) {
						verdict = "error"
						detail = "censord exited"
						t.Error("censord died during the cell")
					}
				}

				if verdict != want && verdict != "error" {
					t.Errorf("%s against %s: %s, want %s", tr.name, cc.name, verdict, want)
				}
				if cc.name == entryBlockCase && verdict == "fail" {
					checkDroppedByCensor(t, l)
				}
			})
		}
	}

	t.Cleanup(func() { writeResults(t, results, expected) })
}

func waitOffPass(t *testing.T, transport string, finished *sync.Map) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Minute)
	for time.Now().Before(deadline) {
		if v, ok := finished.Load(transport + "/off"); ok {
			if v != "pass" {
				t.Fatalf("off cell for %s is %s, entry block is meaningless", transport, v)
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("off cell for %s never finished", transport)
}

const entryBlockCase = "block-ip (entry)"

type matrixCell struct {
	transport, censor, verdict, detail string
}

type censorCase struct {
	name string
	// expect names the result each transport should show when the censor is
	// working; transports omitted default to pass.
	expect map[string]string
	// tcpMustFail: the TCP probe must fail on every address family.
	tcpMustFail bool
	modules     func(t *testing.T, l *lab.Lab) []censor.ModuleConfig
}

func (cc censorCase) want(transport string) string {
	if w, ok := cc.expect[transport]; ok {
		return w
	}
	if len(cc.expect) == 0 {
		return "pass"
	}
	return "pass"
}

var censorCases = []censorCase{
	{name: "off"},
	{name: "block-ip (elsewhere)", modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
		return []censor.ModuleConfig{{Name: "block-ip", Settings: json.RawMessage(
			`{"destinations": ["203.0.113.9", "2001:db8::9"]}`)}}
	}},
	{name: entryBlockCase, expect: map[string]string{"udp": "fail", "tcp": "fail"}, tcpMustFail: true, modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
		return entryBlockSettings(t, l, "drop")
	}},
	{name: "block-ip reset (entry)", expect: map[string]string{"tcp": "fail"}, tcpMustFail: true, modules: func(t *testing.T, l *lab.Lab) []censor.ModuleConfig {
		return entryBlockSettings(t, l, "reset")
	}},
}

type probeCtx struct {
	o4, o6 netip.Addr
}

var probes = []struct {
	name  string
	setup func(t *testing.T, l *lab.Lab) (probeCtx, error)
	probe func(t *testing.T, l *lab.Lab, ctx probeCtx, tcpMustFail bool) error
}{
	{"udp", setupUDP, probeUDP},
	{"tcp", setupTCP, probeTCP},
}

func setupUDP(t *testing.T, l *lab.Lab) (probeCtx, error) {
	dev, server := l.Node(lab.DeviceA), l.Node(lab.Server1)
	space := newM0Space(t, l.Node(lab.Internet), server)
	envelope, version := space.build(t)
	space.install(t, dev, "device-a", envelope)
	space.install(t, server, "server-1", envelope)
	upDev := dev.Start(t, "thinkpol", "up")
	upSrv := server.Start(t, "thinkpol", "up")
	applied := applied(version)
	if err := waitOutput(upSrv, applied, 60*time.Second); err != nil {
		return probeCtx{}, fmt.Errorf("server-1: %w", err)
	}
	if err := waitOutput(upDev, applied, 60*time.Second); err != nil {
		return probeCtx{}, fmt.Errorf("device-a: %w", err)
	}
	if err := waitOutput(upDev, `link up`, 60*time.Second); err != nil {
		return probeCtx{}, err
	}
	o4, o6 := space.overlay(1)
	return probeCtx{o4, o6}, nil
}

func probeUDP(t *testing.T, l *lab.Lab, ctx probeCtx, _ bool) error {
	dev := l.Node(lab.DeviceA)
	if err := pingErr(dev, ctx.o4); err != nil {
		return err
	}
	return pingErr(dev, ctx.o6)
}

func setupTCP(t *testing.T, l *lab.Lab) (probeCtx, error) {
	server := l.Node(lab.Server1)
	_, _ = bringUpM0TCP(t, l)
	return probeCtx{server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)}, nil
}

func probeTCP(t *testing.T, l *lab.Lab, ctx probeCtx, mustFail bool) error {
	dev := l.Node(lab.DeviceA)
	if mustFail {
		if tcpConnect(dev, ctx.o4) == nil || tcpConnect(dev, ctx.o6) == nil {
			return nil
		}
		return fmt.Errorf("tcp blocked to %s and %s", ctx.o4, ctx.o6)
	}
	e4 := tcpConnectRetry(dev, ctx.o4)
	e6 := tcpConnectRetry(dev, ctx.o6)
	if e4 == nil || e6 == nil {
		return nil
	}
	return fmt.Errorf("tcp v4: %v; v6: %v", e4, e6)
}

func tcpConnectRetry(dev *lab.Node, dst netip.Addr) error {
	deadline := time.Now().Add(45 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		last = tcpConnect(dev, dst)
		if last == nil {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	return last
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

var censorLogPath = "/run/censor/verdicts.jsonl"

func processAlive(p *lab.Process) bool {
	select {
	case <-p.Done():
		return false
	default:
		return true
	}
}

func startCensor(t *testing.T, l *lab.Lab, modules []censor.ModuleConfig) (*lab.Process, uint64, uint64) {
	t.Helper()
	b, err := json.Marshal(censor.Config{
		Queue:   100,
		Log:     censorLogPath,
		Modules: modules,
	})
	if err != nil {
		t.Fatal(err)
	}
	router := l.Node(lab.Router)
	router.MustExec(t, "mkdir", "-p", "/run/censor")
	router.WriteFile(t, "/run/censor/config.json", b)
	p := router.Start(t, "censord", "-config", "/run/censor/config.json")
	lab.Eventually(t, 30*time.Second, func() error {
		if !strings.Contains(p.Output(), "censor ready") {
			return fmt.Errorf("censord not ready yet:\n%s", p.Output())
		}
		return nil
	})
	qd, ud, err := nfqueueDrops(router.MustExec(t, "cat", "/proc/net/netfilter/nfnetlink_queue"))
	if err != nil {
		t.Fatal(err)
	}
	return p, qd, ud
}

func censorHealthSince(t *testing.T, l *lab.Lab, qd0, ud0 uint64) error {
	t.Helper()
	router := l.Node(lab.Router)
	qd, ud, err := nfqueueDrops(router.MustExec(t, "cat", "/proc/net/netfilter/nfnetlink_queue"))
	if err != nil {
		return err
	}
	if qd > qd0 || ud > ud0 {
		return fmt.Errorf("nfqueue drops grew queue_dropped=%d→%d user_dropped=%d→%d", qd0, qd, ud0, ud)
	}
	return nil
}

func nfqueueDrops(proc string) (queueDropped, userDropped uint64, err error) {
	for _, line := range strings.Split(proc, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != "100" {
			continue
		}
		qd, err1 := strconv.ParseUint(fields[3], 10, 64)
		ud, err2 := strconv.ParseUint(fields[4], 10, 64)
		if err1 != nil || err2 != nil {
			return 0, 0, fmt.Errorf("parse nfnetlink_queue %q", line)
		}
		return qd, ud, nil
	}
	return 0, 0, fmt.Errorf("queue 100 not in nfnetlink_queue")
}

func checkVerdictLog(t *testing.T, l *lab.Lab, transport string) error {
	t.Helper()
	out := l.Node(lab.Router).MustExec(t, "cat", censorLogPath)
	if strings.TrimSpace(out) == "" {
		return fmt.Errorf("empty verdict log for %s probe", transport)
	}
	return nil
}

func checkDroppedByCensor(t *testing.T, l *lab.Lab) {
	t.Helper()
	server := l.Node(lab.Server1)
	out := l.Node(lab.Router).MustExec(t, "cat", censorLogPath)
	drops := 0
	for _, line := range strings.Split(out, "\n") {
		if line == "" {
			continue
		}
		var e censor.LogEntry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("verdict log line %q: %v", line, err)
		}
		key, err := censor.ParseFlowKey(e.Flow)
		if err != nil {
			continue
		}
		for _, a := range []netip.Addr{server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)} {
			if e.Verdict == censor.Drop && key.Dst == a {
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

func writeResults(t *testing.T, cells []matrixCell, expected int) {
	t.Helper()
	if len(cells) < expected {
		t.Logf("partial matrix run (%d/%d cells), not writing RESULTS.md", len(cells), expected)
		return
	}
	for _, c := range cells {
		if c.verdict == "error" {
			t.Log("matrix cell errored, not writing RESULTS.md")
			return
		}
	}
	if t.Failed() {
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
		if c := strings.Compare(a.censor, b.censor); c != 0 {
			return c
		}
		return 0
	})
	var b strings.Builder
	b.WriteString("# Censor lab results\n\n")
	b.WriteString("<!-- Generated by `make lab` (TestCensorMatrix); do not edit. -->\n\n")
	b.WriteString("Did a transport's data cross the censor in the lab router: pass when it did, fail when the censor stopped it.\n\n")
	b.WriteString("| transport | censor | result | detail |\n|---|---|---|---|\n")
	for _, c := range cells {
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", c.transport, c.censor, c.verdict, escapeCell(c.detail))
	}
	if err := os.WriteFile(filepath.Join(root, "lab", "RESULTS.md"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

func escapeCell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}
