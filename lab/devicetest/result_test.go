//go:build darwin || linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/evidence"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plan"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/safety"
)

// A helper killed mid-run answers nothing; its dead-man's result lands in
// the evidence a little later, and the run waits for it. Without one the
// run says UNKNOWN, never a blank verdict.
func TestWithoutTheHelpersAnswerTheEvidenceSays(t *testing.T) {
	var term bytes.Buffer
	ev, err := evidence.Create(t.TempDir(), "TP-900", time.Now(), &term)
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{ev: ev, deadmanWait: 300 * time.Millisecond}
	if res := r.resultFromEvidence(); res.Verdict != verdictUnknown || len(res.Notes) == 0 || !strings.Contains(term.String(), "waiting up to") {
		t.Errorf("no result anywhere: %+v\n%s", res, term.String())
	}
	write := func(name, verdict string) {
		if err := os.MkdirAll(filepath.Join(ev.Path, "restore"), 0o700); err != nil {
			t.Error(err)
		}
		if err := os.WriteFile(filepath.Join(ev.Path, "restore", name), []byte(`{"verdict":"`+verdict+`","by":"the dead-man"}`), 0o600); err != nil {
			t.Error(err)
		}
	}
	write("result-100.json", "LEFT")
	write("result-200.json", "CLEAN")
	if res := r.resultFromEvidence(); res.Verdict != "CLEAN" || res.By != "the dead-man" {
		t.Errorf("the newest result: %+v", res)
	}

	// The dead-man's result comes while the run waits.
	if err := os.RemoveAll(filepath.Join(ev.Path, "restore")); err != nil {
		t.Fatal(err)
	}
	r.deadmanWait = 10 * time.Second
	go func() { time.Sleep(700 * time.Millisecond); write("result-300.json", "LEFT") }()
	start := time.Now()
	if res := r.resultFromEvidence(); res.Verdict != "LEFT" || time.Since(start) > 5*time.Second {
		t.Errorf("a result written while waiting: %+v after %v", res, time.Since(start))
	}
}

// The last line says "recorded" only when every evidence file was written.
func TestTheLastLineSaysIncompleteWhenEvidenceFailed(t *testing.T) {
	var term bytes.Buffer
	ev, err := evidence.Create(t.TempDir(), "TP-900", time.Now(), &term)
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{ev: ev, plan: plan.Plan{Ticket: "TP-900"}}
	r.report(safety.Result{Verdict: safety.Clean, Run: "r1"}, nil, 0, "ok")
	if !strings.Contains(term.String(), "TP-900 recorded:") {
		t.Errorf("all written:\n%s", term.String())
	}
	ev.WriteFile("plan.txt", nil)
	ev.WriteFile("plan.txt", nil) // exists: fails
	term.Reset()
	r.report(safety.Result{Verdict: safety.Clean, Run: "r1"}, nil, 0, "ok")
	if !strings.Contains(term.String(), "TP-900 INCOMPLETE (1 evidence files failed):") {
		t.Errorf("one failed:\n%s", term.String())
	}
}
