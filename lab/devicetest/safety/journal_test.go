//go:build darwin || linux

package safety

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// journalChild changes the host three times through a journal and is
// killed: "one" applied, "two" applied with its "applied" line never
// written (killed mid-change), "three" with only its intent written.
func journalChild(path string) error {
	dir, err := trusteddir.Make(path)
	if err != nil {
		return err
	}
	j, err := createJournal(dir, "child", "boot-a")
	if err != nil {
		return err
	}
	h := &host{runDir: dir, boot: "boot-a", baseline: &snapshot{}}
	e := &engine{h: h, j: j, armed: isArmed}
	if _, err := e.do(context.Background(), fileSpec("one", "1")); err != nil {
		return err
	}
	two := &fileAction{Name: "two", Content: "2"}
	if _, err := j.intent(two, mustJSON(two)); err != nil {
		return err
	}
	if err := two.apply(context.Background(), h, nil); err != nil {
		return err
	}
	three := &fileAction{Name: "three", Content: "3"}
	if _, err := j.intent(three, mustJSON(three)); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(path, "ready"), nil, 0o600); err != nil {
		return err
	}
	select {}
}

func TestAKilledRunIsUndoneFromItsJournal(t *testing.T) {
	path := filepath.Join(tempDir(t), "run")
	cmd := childCommand(t, nil, "journal-child", path)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	eventually(t, 10*time.Second, "the child's changes", func() bool {
		_, err := os.Stat(filepath.Join(path, "ready"))
		return err == nil
	})
	if err := cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()

	dir := openDir(t, path)
	for _, f := range []string{"file-one", "file-two"} {
		if !present(dir, f) {
			t.Fatalf("%s: the child didn't make it", f)
		}
	}
	j, err := openJournal(dir, "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	var seqs []int
	for _, e := range j.pending() {
		seqs = append(seqs, e.Seq)
	}
	if len(seqs) != 3 || seqs[0] != 3 || seqs[2] != 1 {
		t.Fatalf("pending, newest first: %v", seqs)
	}
	res := (&engine{h: noSurfaces(dir, "boot-a"), j: j, armed: refuseChanges}).restore(t.Context(), "test")
	if res.Verdict != Clean || len(res.Undone) != 3 {
		t.Fatalf("restore: %+v", res)
	}
	for _, f := range []string{"file-one", "file-two", "file-three"} {
		if present(dir, f) {
			t.Errorf("%s is still there", f)
		}
	}
	if err := j.close(); err != nil {
		t.Fatal(err)
	}
	again, err := openJournal(dir, "boot-a")
	if err != nil || !again.closed() || len(again.pending()) != 0 {
		t.Errorf("read back after the restore: %v", err)
	}
}

func TestATornLastLineIsCutOffBeforeTheNextLine(t *testing.T) {
	dir := openDir(t, filepath.Join(tempDir(t), "run"))
	j, err := createJournal(dir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	h := &host{runDir: dir, boot: "boot-a", baseline: &snapshot{}}
	if _, err := (&engine{h: h, j: j, armed: isArmed}).do(t.Context(), fileSpec("one", "1")); err != nil {
		t.Fatal(err)
	}
	if _, err := j.f.WriteString(`{"seq":2,"state":"inte`); err != nil {
		t.Fatal(err)
	}
	_ = j.release()

	// A restore opens it and appends: the torn tail must be gone first,
	// or the new line joins it and the journal never parses again.
	back, err := openJournal(dir, "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	if !back.torn || len(back.entries()) != 1 {
		t.Fatalf("torn %v, entries %+v", back.torn, back.entries())
	}
	res := (&engine{h: noSurfaces(dir, "boot-a"), j: back, armed: refuseChanges}).restore(t.Context(), "test")
	if res.Verdict != Clean {
		t.Fatalf("restore: %+v", res)
	}
	_ = back.release()
	again, err := openJournal(dir, "boot-a")
	if err != nil {
		t.Fatalf("after a line appended past the torn tail: %v", err)
	}
	if e := again.entries(); len(e) != 1 || e[0].State != stateUndone || again.torn {
		t.Errorf("read back: torn %v %+v", again.torn, e)
	}
}

func TestACompleteLineThatDoesntParseIsCorruption(t *testing.T) {
	dir := openDir(t, filepath.Join(tempDir(t), "run"))
	j, err := createJournal(dir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := j.f.WriteString("{\"seq\":2,\"sta\n"); err != nil {
		t.Fatal(err)
	}
	_ = j.release()
	if _, err := openJournal(dir, "boot-a"); err == nil || !strings.Contains(err.Error(), "line 2") {
		t.Errorf("a corrupt complete line: %v", err)
	}
}

func TestAfterAPowerLossOnlyPersistentChangesAreUndone(t *testing.T) {
	for _, tc := range []struct {
		name, boot  string
		processLeft bool
	}{
		// A pid of an earlier boot is someone else's now: never killed.
		{"another boot", "boot-b", true},
		{"the same boot", "boot-a", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sleep, start := startSleep(t)
			dir := openDir(t, filepath.Join(tempDir(t), "run"))
			j, err := createJournal(dir, "r", "boot-a")
			if err != nil {
				t.Fatal(err)
			}
			h := &host{runDir: dir, boot: "boot-a", baseline: &snapshot{}}
			if _, err := (&engine{h: h, j: j, armed: isArmed}).do(t.Context(), fileSpec("kept", "x")); err != nil {
				t.Fatal(err)
			}
			capture := &captureAction{Iface: "en9"}
			seq, err := j.intent(capture, mustJSON(capture))
			if err != nil {
				t.Fatal(err)
			}
			if err := j.mark(seq, stateApplied, mustJSON(captureAction{Iface: "en9", PID: sleep.Process.Pid, Start: start}), nil); err != nil {
				t.Fatal(err)
			}
			_ = j.release()

			j, err = openJournal(dir, tc.boot)
			if err != nil {
				t.Fatal(err)
			}
			res := (&engine{h: noSurfaces(dir, tc.boot), j: j, armed: refuseChanges}).restore(t.Context(), "test")
			if present(dir, "file-kept") {
				t.Error("the persistent change is still there")
			}
			if got := running(sleep.Process.Pid, start); got != tc.processLeft {
				t.Errorf("the capture's process left running: %v, want %v (%+v)", got, tc.processLeft, res)
			}
			if tc.processLeft && len(res.GoneWithReboot) != 1 {
				t.Errorf("gone with the reboot: %v", res.GoneWithReboot)
			}
		})
	}
}
