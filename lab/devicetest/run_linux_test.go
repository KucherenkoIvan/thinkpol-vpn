package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plan"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/safety"
)

// A whole run as root in a lab node, through the real launch script (no
// sudo: the node runs tests as root), helper, dead-man and tcpdump.

func labInterface(t *testing.T) string {
	t.Helper()
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	ifs, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, ifc := range ifs {
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil && ifc.Flags&net.FlagLoopback == 0 && ifc.Flags&net.FlagUp != 0 {
				return ifc.Name
			}
		}
	}
	t.Fatal("no interface with IPv4")
	return ""
}

type labRun struct {
	err    error
	took   time.Duration
	path   string
	record runRecord
	term   string
}

func runAsRoot(t *testing.T, p plan.Plan, phys string) labRun {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var term bytes.Buffer
	r := &runner{plan: p, phys: phys, in: bufio.NewReader(strings.NewReader("yes\n")), out: &term,
		helperCommand: func(args []string) (*exec.Cmd, error) {
			cmd, err := safety.RootCommand(self, args)
			if cmd != nil {
				cmd.Env = append(os.Environ(), childEnv+"=1")
			}
			return cmd, err
		}}
	base := t.TempDir()
	start := time.Now()
	err = r.run(t.Context(), base)
	res := labRun{err: err, took: time.Since(start), term: term.String()}
	m, _ := filepath.Glob(filepath.Join(base, "*-"+p.Ticket))
	if len(m) != 1 {
		t.Fatalf("evidence folders %v\n%s", m, term.String())
	}
	res.path = m[0]
	b, err := os.ReadFile(filepath.Join(res.path, "run.json"))
	if err == nil {
		err = json.Unmarshal(b, &res.record)
	}
	if err != nil {
		t.Fatalf("run.json: %v\n%s", err, term.String())
	}
	if res.record.Restore == nil || res.record.Restore.Verdict != safety.Clean {
		t.Errorf("the restore: %+v\n%s", res.record.Restore, term.String())
	}
	for _, f := range []string{"active", "left"} {
		if _, err := os.Stat(filepath.Join(safety.DefaultStateDir, f)); !os.IsNotExist(err) {
			t.Errorf("a run is still pending (%s): %v", f, err)
		}
	}
	if out, _ := exec.Command("pgrep", "-x", "tcpdump").Output(); len(out) != 0 {
		t.Errorf("tcpdump left running: %s", out)
	}
	return res
}

func TestARunAsRoot(t *testing.T) {
	iface := labInterface(t)
	p := plan.Plan{Ticket: "TP-900", Title: "a lab run", Budget: 2 * time.Minute,
		Capture: plan.Capture{Iface: plan.Physical, Filter: "ip6"},
		Steps: []plan.Step{{Name: "reads", Ops: []plan.Op{
			plan.Read("ip", "route", "show"),
			plan.Do(plan.Change{Kind: safety.KindFile, Params: map[string]string{"name": "lab-step", "content": "x"}}),
			plan.Read("ip", "-o", "link", "show"),
		}}}}
	got := runAsRoot(t, p, iface)
	if got.err != nil || got.record.SelfTest != "ok" || got.record.Steps != 1 {
		t.Fatalf("run: %v %+v\n%s", got.err, got.record, got.term)
	}
	var st struct {
		Capture captureCheck `json:"capture"`
	}
	b, _ := os.ReadFile(filepath.Join(got.path, "selftest", "selftest.json"))
	if err := json.Unmarshal(b, &st); err != nil || !st.Capture.OK || st.Capture.Tries != 1 {
		t.Fatalf("selftest.json: %s %v", b, err)
	}
	decoded, _ := os.ReadFile(filepath.Join(got.path, st.Capture.Decode))
	if !bytes.Contains(decoded, []byte(st.Capture.Positive)) {
		t.Errorf("the decode lacks the marker:\n%s", decoded)
	}
	for _, f := range []string{"captures/" + iface + ".pcap", "captures/markers.jsonl", "steps/01-reads/cmd-001.ip-route-show.out",
		"steps/01-reads/diag.error", "snapshots/00-baseline/routes.out", "snapshots/99-after-restore/routes.out", "plan.txt", "harness.log"} {
		if _, err := os.Stat(filepath.Join(got.path, f)); err != nil {
			t.Errorf("evidence: %v", err)
		}
	}
	if m, _ := filepath.Glob(filepath.Join(got.path, "journal", "journal-*.jsonl")); len(m) != 1 {
		t.Errorf("journal copies %v", m)
	}
	if !strings.Contains(got.term, "devicetest TP-900 recorded: 1 of 1 steps, selftest ok, restore CLEAN") {
		t.Errorf("the last line:\n%s", got.term)
	}
}

func TestABrokenCaptureStopsTheRunWithin10s(t *testing.T) {
	iface := labInterface(t)
	broken := func(capture plan.Capture) plan.Plan {
		return plan.Plan{Ticket: "TP-901", Title: "a broken capture", Budget: 2 * time.Minute, Capture: capture,
			Steps: []plan.Step{{Name: "never", Ops: []plan.Op{
				plan.Do(plan.Change{Kind: safety.KindFile, Params: map[string]string{"name": "never", "content": "x"}}),
			}}}}
	}
	t.Run("it sees nothing", func(t *testing.T) {
		// The markers never reach the interface, as with a capture that
		// is deaf: the positive control isn't seen.
		nft := func(args ...string) {
			if out, err := exec.Command("nft", args...).CombinedOutput(); err != nil {
				t.Fatalf("nft %v: %s %v", args, out, err)
			}
		}
		// At the device's egress, before the capture's tap: the send
		// succeeds (UDP drops ENOBUFS), the packet never shows.
		nft("add", "table", "netdev", "tpdt_test")
		t.Cleanup(func() { _ = exec.Command("nft", "delete", "table", "netdev", "tpdt_test").Run() })
		nft("add", "chain", "netdev", "tpdt_test", "out", "{ type filter hook egress device \""+iface+"\" priority 0 ; }")
		nft("add", "rule", "netdev", "tpdt_test", "out", "udp", "dport", "9", "drop")
		got := runAsRoot(t, broken(plan.Capture{Iface: plan.Physical, Filter: "ip6"}), iface)
		assertStoppedBySelfTest(t, got, "wasn't captured", 2)
	})
	t.Run("no such interface", func(t *testing.T) {
		got := runAsRoot(t, broken(plan.Capture{Iface: "nosuch0"}), iface)
		assertStoppedBySelfTest(t, got, "nosuch0", 0)
	})
}

func assertStoppedBySelfTest(t *testing.T, got labRun, why string, tries int) {
	t.Helper()
	if got.err == nil || got.record.SelfTest == "ok" || !strings.Contains(got.record.SelfTest, why) || got.record.Steps != 0 {
		t.Fatalf("run: %v %+v\n%s", got.err, got.record, got.term)
	}
	// Budget: the self-test's 10 s, plus the helper's start and the
	// restore, which have nothing to do with the capture.
	b, _ := os.ReadFile(filepath.Join(got.path, "selftest", "selftest.json"))
	var st struct {
		Capture captureCheck `json:"capture"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("selftest.json: %s %v", b, err)
	}
	if took, err := time.ParseDuration(st.Capture.Took); err != nil || took > selfTestBudget {
		t.Errorf("the failing check took %s", st.Capture.Took)
	}
	if st.Capture.Tries != tries {
		t.Errorf("tries %d, want %d (markers sent: see captures/markers.jsonl)", st.Capture.Tries, tries)
	}
	if _, err := os.Stat(filepath.Join(got.path, "steps")); !os.IsNotExist(err) {
		t.Errorf("a step ran after the self-test failed: %v", err)
	}
	if !strings.Contains(got.term, "SELF-TEST FAILED") {
		t.Errorf("terminal:\n%s", got.term)
	}
}
