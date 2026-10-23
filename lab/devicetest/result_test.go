//go:build darwin || linux

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/evidence"
)

// A helper killed mid-run answers nothing; its dead-man's result is in the
// evidence, and without one the run says UNKNOWN, never a blank verdict.
func TestWithoutTheHelpersAnswerTheEvidenceSays(t *testing.T) {
	ev, err := evidence.Create(t.TempDir(), "TP-900", time.Now(), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	r := &runner{ev: ev}
	if res := r.resultFromEvidence(); res.Verdict != "UNKNOWN" || len(res.Notes) == 0 {
		t.Errorf("no result anywhere: %+v", res)
	}
	for name, verdict := range map[string]string{"result-100.json": "LEFT", "result-200.json": "CLEAN"} {
		if err := os.MkdirAll(filepath.Join(ev.Path, "restore"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(ev.Path, "restore", name), []byte(`{"verdict":"`+verdict+`","by":"the dead-man"}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if res := r.resultFromEvidence(); res.Verdict != "CLEAN" || res.By != "the dead-man" {
		t.Errorf("the newest result: %+v", res)
	}
}
