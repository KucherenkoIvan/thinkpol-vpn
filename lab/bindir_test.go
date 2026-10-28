package lab

import (
	"os"
	"path/filepath"
	"testing"
)

// Two runs from one checkout get directories of their own; a sweep leaves
// a live run's alone; once both are removed, lab/bin is gone.
func TestRunsHaveTheirOwnBinaryDirectories(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	a, err := newRunDir(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newRunDir(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if a.path == b.path || filepath.Dir(a.path) != binRoot(root) || filepath.Dir(b.path) != binRoot(root) {
		t.Fatalf("run directories %s and %s", a.path, b.path)
	}
	bin := filepath.Join(a.path, "thinkpol")
	if err := os.WriteFile(bin, []byte("a's"), 0o755); err != nil {
		t.Fatal(err)
	}

	if err := RemoveStaleBinaries(ctx, root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("a sweep took a live run's binary: %v", err)
	}

	if err := a.remove(ctx, root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a.path); !os.IsNotExist(err) {
		t.Fatalf("a's directory after its removal: %v", err)
	}
	if _, err := os.Stat(b.path); err != nil {
		t.Fatalf("removing a took b's directory: %v", err)
	}
	if err := b.remove(ctx, root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(binRoot(root)); !os.IsNotExist(err) {
		t.Fatalf("lab/bin after the last run: %v", err)
	}
}

// A run that ended without removing its directory (killed: its lock went
// with it), and what lab/bin held before runs had directories, are swept by
// the next run; lab/bin's other contents stay.
func TestTheNextRunSweepsWhatEndedRunsLeft(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	dead, err := newRunDir(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	_ = dead.lock.Close() // what the kernel does when the run dies
	for _, legacy := range []string{"thinkpol", "tests/x.test", ".censord.123"} {
		path := filepath.Join(binRoot(root), legacy)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, nil, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	other := filepath.Join(binRoot(root), "README")
	if err := os.WriteFile(other, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	next, err := newRunDir(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = next.remove(ctx, root) }()
	entries, err := os.ReadDir(binRoot(root))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 2 || names[0] != "README" || filepath.Join(binRoot(root), names[1]) != next.path {
		t.Errorf("lab/bin after the next run started: %v, want README and %s", names, filepath.Base(next.path))
	}
}

// RemoveBinaries removes the process's directory and forgets it, so a later
// lab builds into a fresh one rather than mounting a deleted path.
func TestRemoveBinariesForgetsTheRun(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	d, err := newRunDir(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	preparedMu.Lock()
	prepared[root] = preparedRun{bin: d}
	preparedMu.Unlock()

	if err := RemoveBinaries(ctx, root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d.path); !os.IsNotExist(err) {
		t.Errorf("the run's directory after RemoveBinaries: %v", err)
	}
	preparedMu.Lock()
	_, still := prepared[root]
	preparedMu.Unlock()
	if still {
		t.Error("the removed directory is still the process's")
	}
	if err := RemoveBinaries(ctx, root); err != nil {
		t.Errorf("a second RemoveBinaries: %v", err)
	}
}
