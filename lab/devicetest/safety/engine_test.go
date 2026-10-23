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
		setup func(h *Host, j *Journal)
		armed func() error
	}{
		{"no baseline", func(h *Host, _ *Journal) { h.Baseline = nil }, isArmed},
		{"no dead-man", func(*Host, *Journal) {}, notArmed},
		{"the journal can't be written", func(_ *Host, j *Journal) { _ = j.release() }, isArmed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := testHost(t, "boot-a")
			j, err := CreateJournal(h.RunDir, "r", "boot-a")
			if err != nil {
				t.Fatal(err)
			}
			tc.setup(h, j)
			_, err = NewEngine(h, j, tc.armed).Do(t.Context(), fileSpec("one", "1"))
			if !errors.Is(err, ErrNoRestorePlan) {
				t.Errorf("Do: %v, want %v", err, ErrNoRestorePlan)
			}
			if present(h.RunDir, "file-one") {
				t.Error("the change was made")
			}
			if len(j.Entries()) != 0 {
				t.Errorf("journal: %+v", j.Entries())
			}
		})
	}
}

func TestAChangeThatIsThereAlreadyIsRefused(t *testing.T) {
	h, _ := testHost(t, "boot-a")
	j, err := CreateJournal(h.RunDir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(h, j, isArmed)
	if _, err := e.Do(t.Context(), fileSpec("one", "1")); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Do(t.Context(), fileSpec("one", "other")); err == nil {
		t.Fatal("a second write of the same file was accepted")
	}
	if err := e.UndoLast(t.Context()); err != nil {
		t.Fatal(err)
	}
	if present(h.RunDir, "file-one") {
		t.Error("UndoLast left the file")
	}
	if err := e.UndoLast(t.Context()); err == nil {
		t.Error("UndoLast with nothing left to undo")
	}
}

func TestAnUnknownKindIsNoAction(t *testing.T) {
	for _, s := range []Spec{
		{Kind: "shell", Params: []byte(`{"cmd":"true"}`)},
		{Kind: KindFile, Params: []byte(`{"name":"../x","content":""}`)},
		{Kind: KindFile, Params: []byte(`{"name":"x","content":"","extra":1}`)},
		{Kind: KindCapture, Params: []byte(`{"iface":"en0; true","filter":""}`)},
	} {
		if _, err := Decode(s); err == nil {
			t.Errorf("%s %s decoded", s.Kind, s.Params)
		}
	}
}

func TestTheRestoreComparesWithTheBaseline(t *testing.T) {
	h, surface := testHost(t, "boot-a")
	j, err := CreateJournal(h.RunDir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	e := NewEngine(h, j, isArmed)
	writeFile(t, surface, "route a\nroute c\n")
	res := e.Restore(t.Context(), "test")
	if res.Verdict != Left || len(res.Left) != 1 {
		t.Fatalf("a changed surface: %+v", res)
	}
	d := res.Left[0]
	if d.Surface != "test-file" || strings.Join(d.Missing, ",") != "route b" || strings.Join(d.Extra, ",") != "route c" || d.Next == "" {
		t.Errorf("difference: %+v", d)
	}
	writeFile(t, surface, "route b\nroute a\n")
	if res := e.Restore(t.Context(), "test"); res.Verdict != Left || !strings.Contains(res.Left[0].String(), "another order") {
		t.Errorf("the same lines reordered: %+v", res)
	}
	writeFile(t, surface, "route a\nroute b\n")
	if res := e.Restore(t.Context(), "test"); res.Verdict != Clean {
		t.Errorf("put back: %+v", res)
	}
}

func TestVerdicts(t *testing.T) {
	for _, tc := range []struct {
		r    Result
		want string
	}{
		{Result{}, Clean},
		{Result{Info: []Difference{{Surface: "dns"}}}, Clean},
		{Result{Failed: []string{"undo 1"}}, Left},
		{Result{Left: []Difference{{Surface: "pf-info"}}}, Left},
		{Result{Left: []Difference{{Surface: "pf-skip"}}}, Reboot},
	} {
		if got := verdict(tc.r); got != tc.want {
			t.Errorf("%+v: %s, want %s", tc.r, got, tc.want)
		}
	}
}
