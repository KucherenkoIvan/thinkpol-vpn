package lab

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Two runs from one checkout get directories of their own; a sweep leaves
// a live run's alone; once both are removed, lab/bin is gone.
func TestRunsHaveTheirOwnBinaryDirectories(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	a, err := newRunBinaries(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newRunBinaries(ctx, root)
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

	if err := removeStaleBinaries(ctx, root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("a sweep took a live run's binary: %v", err)
	}

	if err := a.remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(a.path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("a's directory after its removal: %v", err)
	}
	if _, err := os.Stat(b.path); err != nil {
		t.Fatalf("removing a took b's directory: %v", err)
	}
	if err := b.remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(binRoot(root)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("lab/bin after the last run: %v", err)
	}
}

// A run that ended without removing its directory (killed: its lock went
// with it) is swept by the next run; lab/bin's other contents stay.
func TestTheNextRunSweepsWhatEndedRunsLeft(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	dead, err := newRunBinaries(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	_ = dead.lock.Close() // what the kernel does when the run dies
	other := filepath.Join(binRoot(root), "README")
	if err := os.WriteFile(other, nil, 0o644); err != nil {
		t.Fatal(err)
	}

	next, err := newRunBinaries(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = next.remove(ctx) }()
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

// A kept lab's binaries outlive its run and the next run's sweep, and go
// with labctl down's.
func TestAKeptLabsBinariesStayUntilLabctlDown(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	kept, err := newRunBinaries(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(kept.path, "thinkpol")
	if err := os.WriteFile(bin, nil, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := keepBinaries(kept.path); err != nil {
		t.Fatal(err)
	}
	if err := kept.remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("the kept lab's binary after its run ended: %v", err)
	}

	next, err := newRunBinaries(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	if err := next.remove(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(bin); err != nil {
		t.Fatalf("the kept lab's binary after the next run: %v", err)
	}

	if err := removeStaleBinaries(ctx, root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(binRoot(root)); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("lab/bin after labctl down's sweep: %v", err)
	}
}

// RemoveRunBinaries removes the process's directories and forgets them, so
// a later lab builds into a fresh one rather than mounting a deleted path.
func TestRemoveRunBinariesForgetsTheRun(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	d, err := newRunBinaries(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	preparedMu.Lock()
	prepared[root] = preparedRun{bin: d}
	preparedMu.Unlock()

	if err := RemoveRunBinaries(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(d.path); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the run's directory after RemoveRunBinaries: %v", err)
	}
	preparedMu.Lock()
	_, still := prepared[root]
	preparedMu.Unlock()
	if still {
		t.Error("the removed directory is still the process's")
	}
	if err := RemoveRunBinaries(ctx); err != nil {
		t.Errorf("a second RemoveRunBinaries: %v", err)
	}
}

// Creating and removing a run directory wait for the checkout's lab/bin
// lock, which keeps a sweep from taking a directory not yet locked.
func TestRunDirectoriesWaitForTheCheckoutLock(t *testing.T) {
	ctx := t.Context()
	root := t.TempDir()
	d, err := newRunBinaries(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	unlock, err := lockBinRoot(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	short, cancel := context.WithTimeout(ctx, 600*time.Millisecond)
	defer cancel()
	if e, err := newRunBinaries(short, root); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a run directory created under another's lock: %v, %v", e, err)
	}
	if err := d.remove(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("a run directory removed under another's lock: %v", err)
	}
	unlock()
	if err := d.remove(ctx); err != nil {
		t.Fatal(err)
	}
}

// fatalTB records the first Fatal of a test run in its own goroutine, and
// stops there like testing.T does; Name means start got past its checks.
type fatalTB struct {
	testing.TB
	fatal string
}

func (f *fatalTB) Helper() {}

func (f *fatalTB) Fatal(args ...any) {
	f.fatal = fmt.Sprint(args...)
	runtime.Goexit()
}

func (f *fatalTB) Name() string {
	f.Fatal("started a lab")
	return ""
}

// A lab test in a package whose TestMain doesn't call Main fails before
// it starts a lab: nothing would remove the binaries it runs.
func TestStartWithoutMainFails(t *testing.T) {
	if mainInstalled.Load() {
		t.Skip("this binary runs through Main")
	}
	f := &fatalTB{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		start(f, GoTestTopology(), "")
	}()
	<-done
	if !strings.Contains(f.fatal, "lab.Main") {
		t.Errorf("start without Main: %q", f.fatal)
	}
}

// A package's tests are built once per binary directory, however many labs
// of the process run them: a second build would replace a binary a lab may
// be running. Another directory builds its own.
func TestTestBinariesAreBuiltOncePerDirectory(t *testing.T) {
	t.Cleanup(builtTests.Clear)
	builds := map[string]int{}
	build := func(bin string) func() (bool, error) {
		return func() (bool, error) { builds[bin]++; return true, nil }
	}
	a := filepath.Join(t.TempDir(), "run-a", "tests", "x.test")
	b := filepath.Join(t.TempDir(), "run-b", "tests", "x.test")
	for _, bin := range []string{a, a, b} {
		if built, err := buildTestsOnce(bin, build(bin)); !built || err != nil {
			t.Fatalf("%s: built %v, %v", bin, built, err)
		}
	}
	if builds[a] != 1 || builds[b] != 1 {
		t.Errorf("builds %v, want one per directory", builds)
	}
}
