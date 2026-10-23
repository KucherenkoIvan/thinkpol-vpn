//go:build darwin || linux

package safety

import (
	"errors"
	"strings"
	"testing"
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
	if err := e.undoLast(t.Context()); err != nil {
		t.Fatal(err)
	}
	if present(h.runDir, "file-one") {
		t.Error("undoLast left the file")
	}
	if err := e.undoLast(t.Context()); err == nil {
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
	if err := (&engine{h: h, j: j, armed: isArmed}).undoLast(t.Context()); err == nil || !strings.Contains(err.Error(), "capture") {
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
	if res := e.restore(t.Context(), "test"); res.Verdict != Left || !strings.Contains(res.Left[0].String(), "another order") {
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

// REBOOT is only for a surface whose difference is the core's own change
// surviving its undo (surface.reboot; on macOS, what loading pf.conf sets).
func TestOnlyTheCoresOwnChangeLeftOverIsAReboot(t *testing.T) {
	for _, tc := range []struct {
		r    Result
		want string
	}{
		{Result{}, Clean},
		{Result{Info: []Difference{{Surface: "dns"}}}, Clean},
		{Result{Failed: []string{"undo 1"}}, Left},
		{Result{Left: []Difference{{Surface: "pf-info"}}}, Left},
		{Result{Left: []Difference{{Surface: "pf-anchor-200.AirDrop"}}}, Left},
		{Result{Left: []Difference{{Surface: "pf-anchor-200.AirDrop"}, {Surface: "pf-skip", reboot: true}}}, Reboot},
	} {
		if got := verdict(tc.r); got != tc.want {
			t.Errorf("%+v: %s, want %s", tc.r, got, tc.want)
		}
	}
}
