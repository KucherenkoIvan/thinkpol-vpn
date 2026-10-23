//go:build darwin || linux

package safety

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// journalChild changes the host three times through a journal and is
// killed: "one" applied, "two" applied with its "applied" line never
// written (killed mid-action), "three" with only its intent written.
func journalChild(path string) error {
	dir, err := trusteddir.Make(path)
	if err != nil {
		return err
	}
	j, err := CreateJournal(dir, "child", "boot-a")
	if err != nil {
		return err
	}
	h := &Host{RunDir: dir, Boot: "boot-a", Baseline: &Snapshot{}}
	e := NewEngine(h, j, isArmed)
	if _, err := e.Do(context.Background(), fileSpec("one", "1")); err != nil {
		return err
	}
	two := &FileAction{Name: "two", Content: "2"}
	if _, err := j.Intent(two, mustJSON(two)); err != nil {
		return err
	}
	if _, err := two.Apply(context.Background(), h); err != nil {
		return err
	}
	three := &FileAction{Name: "three", Content: "3"}
	if _, err := j.Intent(three, mustJSON(three)); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(path, "ready"), nil, 0o600); err != nil {
		return err
	}
	time.Sleep(time.Hour)
	return nil
}

func mustJSON(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
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
	j, err := OpenJournal(dir, "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	var seqs []int
	for _, e := range j.Pending() {
		seqs = append(seqs, e.Seq)
	}
	if len(seqs) != 3 || seqs[0] != 3 || seqs[2] != 1 {
		t.Fatalf("pending, last first: %v", seqs)
	}
	h := &Host{RunDir: dir, Boot: "boot-a", Surfaces: []Surface{}, Baseline: &Snapshot{Lines: map[string][]string{}}}
	res := NewEngine(h, j, isArmed).Restore(t.Context(), "test")
	if res.Verdict != Clean || len(res.Undone) != 3 {
		t.Fatalf("restore: %+v", res)
	}
	for _, f := range []string{"file-one", "file-two", "file-three"} {
		if present(dir, f) {
			t.Errorf("%s is still there", f)
		}
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	again, err := OpenJournal(dir, "boot-a")
	if err != nil || !again.Closed() || len(again.Pending()) != 0 {
		t.Errorf("read back after the restore: closed %v, pending %v, %v", again.Closed(), again.Pending(), err)
	}
}

func TestACutLastLineIsIgnored(t *testing.T) {
	dir := openDir(t, filepath.Join(tempDir(t), "run"))
	j, err := CreateJournal(dir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	h := &Host{RunDir: dir, Boot: "boot-a", Baseline: &Snapshot{}}
	if _, err := NewEngine(h, j, isArmed).Do(t.Context(), fileSpec("one", "1")); err != nil {
		t.Fatal(err)
	}
	if _, err := j.f.WriteString(`{"seq":2,"state":"inte`); err != nil {
		t.Fatal(err)
	}
	_ = j.release()
	back, err := OpenJournal(dir, "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	if !back.Torn || len(back.Entries()) != 1 || back.Entries()[0].State != StateApplied {
		t.Errorf("torn %v, entries %+v", back.Torn, back.Entries())
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
			sleep := startSleep(t)
			start, err := startTime(sleep.Process.Pid)
			if err != nil {
				t.Fatal(err)
			}
			dir := openDir(t, filepath.Join(tempDir(t), "run"))
			j, err := CreateJournal(dir, "r", "boot-a")
			if err != nil {
				t.Fatal(err)
			}
			h := &Host{RunDir: dir, Boot: "boot-a", Baseline: &Snapshot{}}
			if _, err := NewEngine(h, j, isArmed).Do(t.Context(), fileSpec("kept", "x")); err != nil {
				t.Fatal(err)
			}
			capture := &CaptureAction{Iface: "en9"}
			seq, err := j.Intent(capture, mustJSON(capture))
			if err != nil {
				t.Fatal(err)
			}
			if err := j.Mark(seq, StateApplied, mustJSON(CaptureAction{Iface: "en9", PID: sleep.Process.Pid, Start: start}), nil); err != nil {
				t.Fatal(err)
			}
			_ = j.release()

			j, err = OpenJournal(dir, tc.boot)
			if err != nil {
				t.Fatal(err)
			}
			h = &Host{RunDir: dir, Boot: tc.boot, Surfaces: []Surface{}, Baseline: &Snapshot{Lines: map[string][]string{}}}
			res := NewEngine(h, j, isArmed).Restore(t.Context(), "test")
			if present(dir, "file-kept") {
				t.Error("the persistent change is still there")
			}
			if got := sameProcess(sleep.Process.Pid, start); got != tc.processLeft {
				t.Errorf("the capture's process left running: %v, want %v (%+v)", got, tc.processLeft, res)
			}
			if tc.processLeft && len(res.GoneWithReboot) != 1 {
				t.Errorf("gone with the reboot: %v", res.GoneWithReboot)
			}
		})
	}
}
