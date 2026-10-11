//go:build unix

package lab

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

// Locks are per open file, so a second open in this process stands in for
// another run.
func TestPerfLockExcludesLabSlots(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	dir, err := lockDir()
	if err != nil {
		t.Fatal(err)
	}
	perf := filepath.Join(dir, "perf.lock")
	short := func() context.Context {
		ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
		t.Cleanup(cancel)
		return ctx
	}

	// A lab slot holds the perf lock shared: a perf run waits.
	releaseSlot, err := acquireHostSlot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := AcquirePerfLock(short()); err == nil {
		t.Fatal("a perf run started while a lab held a slot")
	}
	releaseSlot()

	releasePerf, err := AcquirePerfLock(short())
	if err != nil {
		t.Fatalf("no perf run with no lab up: %v", err)
	}
	// Another run's lab waits for it...
	if f, ok, err := tryLockMode(perf, false); err != nil || ok {
		_ = f.Close()
		t.Fatalf("another run's lab could start during a perf run (%v)", err)
	}
	// ...but the perf run's own labs don't.
	releaseOwn, err := acquireHostSlot(short())
	if err != nil {
		t.Fatalf("the perf run's own lab waited: %v", err)
	}
	releaseOwn()
	releasePerf()
	if f, ok, err := tryLockMode(perf, false); err != nil || !ok {
		t.Fatalf("labs still kept out after the perf run (%v)", err)
	} else {
		_ = f.Close()
	}
}
