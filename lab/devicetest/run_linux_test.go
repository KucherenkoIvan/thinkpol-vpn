package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
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
	return runAsRootTyping(t, p, phys, "yes\n")
}

// runAsRootTyping runs p with typed as the owner's terminal input.
func runAsRootTyping(t *testing.T, p plan.Plan, phys, typed string) labRun {
	t.Helper()
	return runAsRootWith(t, p, phys, func(*runner) io.Reader { return strings.NewReader(typed) })
}

// runAsRootWith runs p with input's reader as the owner's terminal input.
func runAsRootWith(t *testing.T, p plan.Plan, phys string, input func(*runner) io.Reader) labRun {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	var term bytes.Buffer
	r := &runner{plan: p, phys: phys, out: &term,
		helperCommand: func(args []string) (*exec.Cmd, error) {
			cmd, err := safety.RootCommand(self, args)
			if cmd != nil {
				cmd.Env = append(os.Environ(), childEnv+"=1")
			}
			return cmd, err
		}}
	r.in = bufio.NewReader(input(r))
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
	// Nothing is pending: `devicetest restore`'s root side has nothing to do.
	cmd, err := safety.RootCommand(self, []string{"root-restore"})
	if err != nil {
		t.Fatal(err)
	}
	cmd.Env = append(os.Environ(), childEnv+"=1")
	out, _ := cmd.Output()
	var resp safety.Response
	if err := json.Unmarshal(out, &resp); err != nil || resp.Result == nil || resp.Result.Verdict != safety.Nothing {
		t.Errorf("a run is still pending: %s %v", out, err)
	}
	if out, _ := exec.Command("pgrep", "-x", "tcpdump").Output(); len(out) != 0 {
		t.Errorf("tcpdump left running: %s", out)
	}
	return res
}

func TestAWholeRunRecordsItsEvidenceAndRestoresClean(t *testing.T) {
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

// An ask prints its prompt after the time, waits for the owner's line and
// keeps it: in the step's folder with when it was asked and answered, in
// notes.md and in the transcript.
func TestAnAskWaitsForTheOwnerAndKeepsTheNote(t *testing.T) {
	iface := labInterface(t)
	p := plan.Plan{Ticket: "TP-902", Title: "an ask", Budget: 2 * time.Minute,
		Steps: []plan.Step{{Name: "by-hand", Ops: []plan.Op{
			plan.Read("ip", "-o", "link", "show"),
			plan.Ask("Turn Wi-Fi off."),
			plan.Read("ip", "route", "show"),
		}}}}
	got := runAsRootTyping(t, p, iface, "yes\nwifi off at 10:02, a second try\n")
	if got.err != nil || got.record.Steps != 1 {
		t.Fatalf("run: %v %+v\n%s", got.err, got.record, got.term)
	}
	if !regexp.MustCompile(`(?m)^\d\d:\d\d:\d\d Turn Wi-Fi off\. Then type your note, if any, and press Enter \(budget: \dm\d+s left\): `).MatchString(got.term) {
		t.Errorf("no timestamped prompt:\n%s", got.term)
	}
	var ask struct {
		Ask, Note       string
		Asked, Answered time.Time
	}
	b, err := os.ReadFile(filepath.Join(got.path, "steps/01-by-hand/ask-002.json"))
	if err == nil {
		err = json.Unmarshal(b, &ask)
	}
	if err != nil || ask.Ask != "Turn Wi-Fi off." || ask.Note != "wifi off at 10:02, a second try" ||
		ask.Asked.IsZero() || ask.Answered.Before(ask.Asked) {
		t.Errorf("the ask's record: %s %v", b, err)
	}
	for _, f := range []string{"notes.md", "harness.log"} {
		if b, _ := os.ReadFile(filepath.Join(got.path, f)); !bytes.Contains(b, []byte(`Turn Wi-Fi off.`)) ||
			!bytes.Contains(b, []byte(`"wifi off at 10:02, a second try"`)) {
			t.Errorf("%s lacks the ask and its note:\n%s", f, b)
		}
	}
	if _, err := os.Stat(filepath.Join(got.path, "steps/01-by-hand/cmd-003.ip-route-show.out")); err != nil {
		t.Errorf("the read after the ask: %v", err)
	}
}

// The helper killed during an ask (as by its dead-man): between asks
// nothing else calls it, so the asks' checks say the capture stopped,
// right after that ask and again right before the next prompt.
func TestAnAskAfterTheHelperDiedSaysTheCaptureStopped(t *testing.T) {
	iface := labInterface(t)
	p := plan.Plan{Ticket: "TP-903", Title: "the helper dies during an ask", Budget: 2 * time.Minute,
		Capture: plan.Capture{Iface: plan.Physical, Filter: "ip6"},
		Steps:   []plan.Step{{Name: "first", Ops: []plan.Op{plan.Ask("Connect.")}}, {Name: "second", Ops: []plan.Op{plan.Ask("Look up a name.")}}}}
	got := runAsRootWith(t, p, iface, func(r *runner) io.Reader {
		// The launch script execs the helper: its pid is the helper's.
		return &typing{lines: []string{"yes\n", "connected\n", "a name\n"}, before: map[int]func(){1: func() { _ = r.c.cmd.Process.Kill() }}}
	})
	if got.record.SelfTest != "ok" || got.record.Steps != 2 || got.record.Restore == nil || !strings.HasPrefix(got.record.Restore.By, "the dead-man") {
		t.Fatalf("run: %v %+v\n%s", got.err, got.record, got.term)
	}
	stopped := `THE CAPTURE STOPPED at \d\d:\d\d:\d\d: the helper doesn't answer \(the helper: [^)]+\): its dead-man restores the run; what you do now isn't recorded`
	for name, re := range map[string]string{
		"after the ask": `asked: Connect\..*\n\d\d:\d\d:\d\d ` + stopped + `\n`,
		"before the next prompt": `\n\d\d:\d\d:\d\d ` + stopped + `\n\d\d:\d\d:\d\d Look up a name\. Then type your note, if any, ` +
			`and press Enter \(budget: 1m\d+s left\): `,
	} {
		if !regexp.MustCompile(re).MatchString(got.term) {
			t.Errorf("%s: no match for %s in\n%s", name, re, got.term)
		}
	}
	if b, err := os.ReadFile(filepath.Join(got.path, "recording-stopped.txt")); err != nil || !regexp.MustCompile(stopped).Match(b) {
		t.Errorf("recording-stopped.txt: %s %v", b, err)
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
	b, _ := os.ReadFile(filepath.Join(got.path, "selftest", "selftest.json"))
	var st struct {
		Took    string       `json:"took"`
		Capture captureCheck `json:"capture"`
	}
	if err := json.Unmarshal(b, &st); err != nil {
		t.Fatalf("selftest.json: %s %v", b, err)
	}
	// The check's own Took and the self-test's took are measured by the
	// code under test; got.took is this test's clock around the whole run
	// (helper start and restore included), so a Took that leaves part of
	// the check out can't pass.
	if took, err := time.ParseDuration(st.Capture.Took); err != nil || took > selfTestBudget {
		t.Errorf("the failing check took %s", st.Capture.Took)
	}
	if took, err := time.ParseDuration(st.Took); err != nil || took > selfTestBudget {
		t.Errorf("the self-test took %s", st.Took)
	}
	if got.took > selfTestBudget {
		t.Errorf("the whole run took %v, over the self-test's %v", got.took, selfTestBudget)
	}
	t.Logf("the whole run took %v; the self-test %s, its capture check %s", got.took.Round(time.Millisecond), st.Took, st.Capture.Took)
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
