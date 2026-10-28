//go:build darwin || linux

package safety

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestNothingChangesWithoutARestorePlan(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(h *host, j *journal)
		armed func() error
	}{
		{"no baseline", func(h *host, _ *journal) { h.baseline = nil }, isArmed},
		{"no dead-man", func(*host, *journal) {}, notArmed},
		{"the journal can't be written", func(_ *host, j *journal) { _ = j.release() }, isArmed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := testHost(t, "boot-a")
			j, err := createJournal(h.runDir, "r", "boot-a")
			if err != nil {
				t.Fatal(err)
			}
			tc.setup(h, j)
			_, err = (&engine{h: h, j: j, armed: tc.armed}).do(t.Context(), fileSpec("one", "1"))
			if !errors.Is(err, errNoRestorePlan) {
				t.Errorf("do: %v, want %v", err, errNoRestorePlan)
			}
			if present(h.runDir, "file-one") {
				t.Error("the change was made")
			}
			if len(j.entries()) != 0 {
				t.Errorf("journal: %+v", j.entries())
			}
		})
	}
}

func TestAChangeThatIsThereAlreadyIsRefused(t *testing.T) {
	h, _ := testHost(t, "boot-a")
	j, err := createJournal(h.runDir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{h: h, j: j, armed: isArmed}
	if _, err := e.do(t.Context(), fileSpec("one", "1")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.do(t.Context(), fileSpec("one", "other")); err == nil {
		t.Fatal("a second write of the same file was accepted")
	}
	if _, err := e.undoLast(t.Context()); err != nil {
		t.Fatal(err)
	}
	if present(h.runDir, "file-one") {
		t.Error("undoLast left the file")
	}
	if _, err := e.undoLast(t.Context()); err == nil {
		t.Error("undoLast with nothing left to undo")
	}
}

func TestUndoLastNeverEndsTheRunsCapture(t *testing.T) {
	h, _ := testHost(t, "boot-a")
	j, err := createJournal(h.runDir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	capture := &captureAction{Iface: "en9"}
	if _, err := j.intent(capture, mustJSON(capture)); err != nil {
		t.Fatal(err)
	}
	if _, err := (&engine{h: h, j: j, armed: isArmed}).undoLast(t.Context()); err == nil || !strings.Contains(err.Error(), "capture") {
		t.Errorf("undoLast with a capture newest: %v", err)
	}
	if p := j.pending(); len(p) != 1 {
		t.Errorf("pending: %+v", p)
	}
}

func TestTheRestoreComparesWithTheBaseline(t *testing.T) {
	h, surface := testHost(t, "boot-a")
	j, err := createJournal(h.runDir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	e := &engine{h: h, j: j, armed: refuseChanges}
	writeFile(t, surface, "route a\nroute c\n")
	res := e.restore(t.Context(), "test")
	if res.Verdict != Left || len(res.Left) != 1 {
		t.Fatalf("a changed surface: %+v", res)
	}
	d := res.Left[0]
	if d.Surface != "test-file" || strings.Join(d.Missing, ",") != "route b" || strings.Join(d.Extra, ",") != "route c" || d.Next == "" {
		t.Errorf("difference: %+v", d)
	}
	writeFile(t, surface, "route b\nroute a\n")
	if res := e.restore(t.Context(), "test"); res.Verdict != Left || len(res.Left) != 1 || !strings.Contains(strings.Join(res.Left[0].Extra, " "), "another order") {
		t.Errorf("the same lines reordered: %+v", res)
	}
	writeFile(t, surface, "route a\nroute b\n")
	if res := e.restore(t.Context(), "test"); res.Verdict != Clean {
		t.Errorf("put back: %+v", res)
	}
}

func TestSnapshotsAreWrittenOnceUnderTheCoresNames(t *testing.T) {
	h, surface := testHost(t, "boot-a")
	writeFile(t, surface, "route z\n")
	if _, err := h.snapshot(t.Context(), baselineName); err == nil {
		t.Fatal("the baseline was taken again")
	}
	base, err := loadSnapshot(h, baselineName)
	if err != nil || strings.Join(base.Lines["test-file"], ",") != "route a,route b" {
		t.Fatalf("the baseline on disk: %+v %v", base, err)
	}
	for _, want := range []string{afterName, afterName + "-2", afterName + "-3"} {
		s, err := h.snapshot(t.Context(), afterName)
		if err != nil || s.Name != want {
			t.Errorf("after-restore snapshot named %q, want %q: %v", s.Name, want, err)
		}
	}
}

// REBOOT is only for the core's own pf change surviving its undo
// (pfSurvived: pf still lists this run's skip); anything else failed or
// left over is LEFT.
func TestTheVerdictTable(t *testing.T) {
	for _, tc := range []struct {
		r          Result
		pfSurvived bool
		want       string
	}{
		{Result{}, false, Clean},
		{Result{Info: []Difference{{Surface: "dns"}}}, false, Clean},
		{Result{Failed: []string{"undo 1"}}, false, Left},
		{Result{Left: []Difference{{Surface: "pf-skip"}}}, false, Left},
		{Result{Left: []Difference{{Surface: "pf-anchor-200.AirDrop"}}}, false, Left},
		{Result{Failed: []string{"undo 1"}, Left: []Difference{{Surface: "pf-skip"}}}, true, Reboot},
	} {
		if got := verdict(tc.r, tc.pfSurvived); got != tc.want {
			t.Errorf("%+v, pf survived %v: %s, want %s", tc.r, tc.pfSurvived, got, tc.want)
		}
	}
}

// UndoLast's answer says what the undo did, as a restore's Undone does,
// so the user side reports it.
func TestUndoLastSaysWhatItsUndoDid(t *testing.T) {
	h, _ := testHost(t, "boot-a")
	j, err := createJournal(h.runDir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	r := &runState{engine: &engine{h: h, j: j, armed: isArmed}}
	if resp := r.serve(t.Context(), Request{ID: 1, Op: OpDo, Change: ptr(fileSpec("one", "1"))}); !resp.OK {
		t.Fatalf("do: %+v", resp)
	}
	resp := r.serve(t.Context(), Request{ID: 2, Op: OpUndoLast})
	if !resp.OK || !strings.HasPrefix(resp.Did, "1: ") || !strings.HasSuffix(resp.Did, ": removed") {
		t.Errorf("undo_last: %+v", resp)
	}
}

func ptr[T any](v T) *T { return &v }

// Every command the core runs is in a process group of its own, so a
// signal for the terminal's group never reaches a pfctl mid-load.
func TestACommandRunsInAProcessGroupOfItsOwn(t *testing.T) {
	pidFile := filepath.Join(tempDir(t), "pid")
	done := make(chan output, 1)
	go func() {
		done <- run(t.Context(), []string{"/bin/sh", "-c", "echo $$ > " + pidFile + "; exec /bin/sleep 1"}, nil)
	}()
	var pid int
	eventually(t, 5*time.Second, "the command's pid", func() bool {
		b, err := os.ReadFile(pidFile)
		pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		return err == nil && pid > 0
	})
	pgid, err := syscall.Getpgid(pid)
	if err != nil || pgid != pid || pgid == syscall.Getpgrp() {
		t.Errorf("pid %d in process group %d (%v); the test's is %d", pid, pgid, err, syscall.Getpgrp())
	}
	<-done
}
