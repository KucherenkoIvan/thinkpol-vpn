//go:build darwin || linux

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/evidence"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plan"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/safety"
)

// The user side's steps without root: plans of asks need no helper, and
// one that changes something talks to fakeHelper, the test binary
// answering the helper's protocol (nothing runs as root, nothing reaches
// the host).

// fakeHelperEnv makes the test binary fakeHelper.
const fakeHelperEnv = "TPDT_FAKE_HELPER"

// fakeHelperDid is what fakeHelper's undo_last says it undid.
const fakeHelperDid = `2: load pf's main ruleset: "set skip on lo", then /etc/pf.conf: loaded /etc/pf.conf`

// fakeHelper refuses every change, as the core refuses lo0's load while
// lo's skip is still listed, and says every undo_last undid fakeHelperDid.
func fakeHelper(in io.Reader, out io.Writer) {
	enc := json.NewEncoder(out)
	_ = enc.Encode(safety.Response{OK: true})
	sc := bufio.NewScanner(in)
	for sc.Scan() {
		var req safety.Request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			return
		}
		resp := safety.Response{ID: req.ID, OK: true}
		switch req.Op {
		case safety.OpDo:
			resp.OK, resp.Err = false, `load pf's main ruleset: "set skip on lo0", then /etc/pf.conf: refused: pf-skip differs from the baseline`
		case safety.OpUndoLast:
			resp.Did = fakeHelperDid
		case safety.OpRestore:
			resp.Result = &safety.Result{Verdict: safety.Clean, By: "the helper: asked"}
			_ = enc.Encode(resp)
			return
		}
		_ = enc.Encode(resp)
	}
}

// typing is the owner's terminal: one line a read, each after its hook,
// then the end of input.
type typing struct {
	lines  []string
	before map[int]func()
	n      int
}

func (t *typing) Read(p []byte) (int, error) {
	if t.n >= len(t.lines) {
		return 0, io.EOF
	}
	if f := t.before[t.n]; f != nil {
		f()
	}
	n := copy(p, t.lines[t.n])
	t.n++
	return n, nil
}

type stepsRun struct {
	r    *runner
	term *bytes.Buffer
}

// newStepsRun is a runner for p's steps alone, its evidence in a
// temporary folder; input reads what the owner types.
func newStepsRun(t *testing.T, p plan.Plan, input func(*runner) io.Reader) stepsRun {
	t.Helper()
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}
	var term bytes.Buffer
	ev, err := evidence.Create(t.TempDir(), p.Ticket, time.Now(), &term)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ev.Close() })
	r := &runner{plan: p, out: &term, ev: ev, deadline: time.Now().Add(p.Budget)}
	r.in = bufio.NewReader(input(r))
	return stepsRun{r: r, term: &term}
}

func asks(texts ...string) []plan.Step {
	var st []plan.Step
	for i, text := range texts {
		st = append(st, plan.Step{Name: fmt.Sprintf("ask-%d", i+1), Ops: []plan.Op{plan.Ask(text)}})
	}
	return st
}

func (s stepsRun) exists(rel string) bool {
	_, err := os.Stat(filepath.Join(s.r.ev.Path, rel))
	return err == nil
}

func (s stepsRun) read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(s.r.ev.Path, rel))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Input that ends during an ask stops the run there: nobody is left to
// answer the next one.
func TestAnAskAtTheEndOfInputStopsTheRun(t *testing.T) {
	p := plan.Plan{Ticket: "TP-904", Budget: time.Minute, Steps: asks("Turn Wi-Fi off.", "Turn Wi-Fi on.")}
	s := newStepsRun(t, p, func(*runner) io.Reader { return &typing{} })
	n, err := s.r.steps(t.Context())
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("steps: %d, %v\n%s", n, err, s.term)
	}
	if !strings.Contains(s.read(t, "steps/01-ask-1/ask-001.json"), `"error": "EOF"`) {
		t.Errorf("the ask's record lacks the end of input")
	}
	if s.exists("steps/02-ask-2") {
		t.Errorf("the second step ran:\n%s", s.term)
	}
}

// A Ctrl-C during a step's last ask ends the run before the next step:
// no "step 2" line, no marker for it, no folder.
func TestACtrlCDuringAStepsLastAskStartsNoOtherStep(t *testing.T) {
	p := plan.Plan{Ticket: "TP-905", Budget: time.Minute, Steps: asks("Turn Wi-Fi off.", "Turn Wi-Fi on.")}
	s := newStepsRun(t, p, func(r *runner) io.Reader {
		return &typing{lines: []string{"off\n", "on\n"}, before: map[int]func(){0: func() { r.stopped.Store(true) }}}
	})
	n, err := s.r.steps(t.Context())
	if n != 1 || !errors.Is(err, errStopped) {
		t.Fatalf("steps: %d, %v\n%s", n, err, s.term)
	}
	if strings.Contains(s.term.String(), "step 2") || s.exists("steps/02-ask-2") ||
		strings.Contains(s.read(t, "captures/markers.jsonl"), `"ask-2"`) {
		t.Errorf("the second step started:\n%s", s.term)
	}
}

// A restore between two asks (the dead-man's, its budget run out) is said
// after the first and again right before the second's prompt, and kept
// in the evidence; each prompt says how much of the budget is left.
func TestAnAskSaysTheRunWasRestoredSinceTheLastOne(t *testing.T) {
	p := plan.Plan{Ticket: "TP-906", Budget: 15 * time.Minute, Steps: asks("Connect.", "Browse one light page.")}
	s := newStepsRun(t, p, func(r *runner) io.Reader {
		return &typing{lines: []string{"connected\n", "a page\n"}, before: map[int]func(){0: func() {
			b, _ := json.Marshal(safety.Result{Verdict: safety.Clean, By: "the dead-man: the deadline (15m0s) has passed with no restore making progress"})
			r.ev.WriteFile(fmt.Sprintf("restore/result-%d.json", time.Now().UnixNano()), b)
		}}}
	})
	if n, err := s.r.steps(t.Context()); n != 2 || err != nil {
		t.Fatalf("steps: %d, %v\n%s", n, err, s.term)
	}
	stopped := `THE RUN STOPPED at \d\d:\d\d:\d\d: the run was restored \(CLEAN\) by the dead-man: the deadline \(15m0s\) has passed with no restore making progress; what you do now isn't recorded`
	for name, re := range map[string]string{
		"the first prompt": `(?m)^\d\d:\d\d:\d\d Connect\. Then type your note, if any, and press Enter \(budget: 1[45]m\d+s left\): `,
		"after the first":  `asked: Connect\..*\n\d\d:\d\d:\d\d ` + stopped + `\n`,
		"before the second": `\n\d\d:\d\d:\d\d ` + stopped + `\n\d\d:\d\d:\d\d Browse one light page\. Then type your note, if any, ` +
			`and press Enter \(budget: 1[45]m\d+s left\): `,
	} {
		if !regexp.MustCompile(re).MatchString(s.term.String()) {
			t.Errorf("%s: no match for %s in\n%s", name, re, s.term)
		}
	}
	if !regexp.MustCompile(stopped).MatchString(s.read(t, "recording-stopped.txt")) {
		t.Errorf("recording-stopped.txt: %s", s.read(t, "recording-stopped.txt"))
	}
	var first, second struct {
		RecordingBefore string `json:"recording_before"`
		RecordingAfter  string `json:"recording_after"`
	}
	_ = json.Unmarshal([]byte(s.read(t, "steps/01-ask-1/ask-001.json")), &first)
	_ = json.Unmarshal([]byte(s.read(t, "steps/02-ask-2/ask-001.json")), &second)
	if first.RecordingBefore != "ok" || !strings.HasPrefix(first.RecordingAfter, "THE RUN STOPPED") ||
		!strings.HasPrefix(second.RecordingBefore, "THE RUN STOPPED") {
		t.Errorf("the asks' records: %+v %+v", first, second)
	}
	s.r.deadline = time.Now().Add(-time.Minute)
	if got := s.r.budgetLeft(); !strings.HasPrefix(got, "the budget ran out at ") {
		t.Errorf("past the deadline: %q", got)
	}
}

// A capture that missed its marker because tcpdump ended (at its packet
// limit, say) says so with tcpdump's own counts and the time it wrote
// them; one with no such words sees nothing.
func TestACaptureThatEndedSaysTcpdumpsCounts(t *testing.T) {
	s := newStepsRun(t, plan.Plan{Ticket: "TP-907", Budget: time.Minute}, func(*runner) io.Reader { return &typing{} })
	s.r.capIface = "en9"
	if why, _ := s.r.captureEnded(); why != "a marker sent on en9 wasn't captured (2 tries): the capture sees nothing" {
		t.Errorf("no stderr: %q", why)
	}
	s.r.ev.WriteFile("captures/en9.tcpdump.err", []byte("tcpdump: listening on en9, link-type EN10MB (Ethernet), snapshot length 128 bytes\n"+
		"200000 packets captured\n200417 packets received by filter\n0 packets dropped by kernel\n"))
	why, at := s.r.captureEnded()
	if why != "tcpdump on en9 ended (200000 packets captured; 200417 packets received by filter; 0 packets dropped by kernel)" ||
		time.Since(at) > time.Minute {
		t.Errorf("ended: %q at %v", why, at)
	}
}

// A change that fails and is passed over: the stop prompt says what the
// plan says to type, and the step's folder says what it holds: listings
// without the change, and an undo of an earlier step's change.
func TestAChangePassedOverLeavesANoteInItsStep(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := plan.Plan{Ticket: "TP-908", Budget: time.Minute, Steps: []plan.Step{{Name: "skip-on-lo0", Ops: []plan.Op{
		plan.IfFailed(plan.Do(plan.PfSkip("lo0")), "Refused while lo's skip is listed: press Enter."),
		plan.Read("pfctl", "-s", "Interfaces", "-v"),
		plan.UndoLast(),
	}}}}
	s := newStepsRun(t, p, func(*runner) io.Reader { return &typing{lines: []string{"continue\n"}} })
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), fakeHelperEnv+"=1")
	if s.r.c, err = startClient(cmd); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = s.r.c.restore() })
	if n, err := s.r.steps(t.Context()); n != 1 || err != nil {
		t.Fatalf("steps: %d, %v\n%s", n, err, s.term)
	}
	if !strings.Contains(s.term.String(), "Refused while lo's skip is listed: press Enter. Type continue to go on, or press Enter to restore and end the run:") {
		t.Errorf("the stop prompt:\n%s", s.term)
	}
	note := s.read(t, "steps/01-skip-on-lo0/NOTE.txt")
	for _, want := range []string{
		"Operation 1, this step's change (", "failed and was passed over (continue): ", "refused: pf-skip differs from the baseline",
		"recorded without it",
		"Operation 3, the undo, acted on the newest change still made (not this step's, which failed): " + fakeHelperDid,
	} {
		if !strings.Contains(note, want) {
			t.Errorf("NOTE.txt lacks %q:\n%s", want, note)
		}
	}
}
