package lab

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

// runDirPrefix starts the name of every run's directory in lab/bin.
const runDirPrefix = "run-"

// runLockName is the lock file a run holds inside its directory.
const runLockName = ".lock"

// keptMarker, in a run's directory, says a kept lab (KeepEnv) still mounts
// it: the run leaves it behind, and only labctl down removes it.
const keptMarker = ".kept"

// binRoot is the checkout's lab/bin, the parent of every run's directory.
func binRoot(root string) string { return filepath.Join(root, "lab", "bin") }

// runBinaries is this process's binary directory, lab/bin/run-*, locked
// while the process holds it.
type runBinaries struct {
	root string // the checkout
	path string
	lock *os.File
}

// lockBinRoot serializes creating, sweeping and removing run directories of
// one checkout, so a sweep never takes a directory between its creation and
// its lock, and lab/bin is never removed under a run creating its
// directory. The lock file is the checkout's own, in lab/.run, not in
// lab/bin, which goes once empty.
func lockBinRoot(ctx context.Context, root string) (func(), error) {
	dir := filepath.Join(root, "lab", ".run")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("lab: %w", err)
	}
	return waitLock(ctx, "the lab/bin lock", filepath.Join(dir, "bin.lock"))
}

// newRunBinaries sweeps away what ended runs left in lab/bin and creates
// this run's directory, locked.
func newRunBinaries(ctx context.Context, root string) (*runBinaries, error) {
	unlock, err := lockBinRoot(ctx, root)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := sweepBinRoot(root, false); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(binRoot(root), 0o755); err != nil {
		return nil, fmt.Errorf("lab: run directory: %w", err)
	}
	path, err := os.MkdirTemp(binRoot(root), runDirPrefix)
	if err != nil {
		return nil, fmt.Errorf("lab: run directory: %w", err)
	}
	// MkdirTemp makes it 0700; the nodes' root reads it through the mount,
	// which on Linux hosts keeps the owner.
	if err := os.Chmod(path, 0o755); err != nil {
		return nil, errors.Join(fmt.Errorf("lab: run directory: %w", err), os.RemoveAll(path))
	}
	lock, ok, err := tryLockMode(filepath.Join(path, runLockName), true)
	if err == nil && !ok {
		err = errors.New("lab: a fresh run directory is locked already")
	}
	if err != nil {
		return nil, errors.Join(err, os.RemoveAll(path))
	}
	return &runBinaries{root: root, path: path, lock: lock}, nil
}

// keepBinaries marks the run directory at dir as mounted by a kept lab.
func keepBinaries(dir string) error {
	return os.WriteFile(filepath.Join(dir, keptMarker), nil, 0o644)
}

// remove deletes the run's directory, and lab/bin when no other run has
// one there; a kept lab's directory stays, unlocked, for labctl down.
func (d *runBinaries) remove(ctx context.Context) error {
	unlock, err := lockBinRoot(ctx, d.root)
	if err != nil {
		return err
	}
	defer unlock()
	defer func() { _ = d.lock.Close() }()
	if _, err := os.Stat(filepath.Join(d.path, keptMarker)); err == nil {
		return nil
	}
	return errors.Join(os.RemoveAll(d.path), removeIfEmpty(binRoot(d.root)))
}

// runDirLive reports whether a live run holds the run directory at path.
// The caller holds lockBinRoot, so a run that has ended can't come back.
func runDirLive(path string) (bool, error) {
	lock, free, err := tryLockMode(filepath.Join(path, runLockName), true)
	if err != nil || !free {
		return !free, err
	}
	return false, lock.Close()
}

// sweepBinRoot removes the directories of runs that ended without removing
// them (their lock is free), with withKept also those kept labs mount,
// then lab/bin itself if that leaves it empty. The caller holds
// lockBinRoot.
func sweepBinRoot(root string, withKept bool) error {
	entries, err := os.ReadDir(binRoot(root))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lab: %w", err)
	}
	var errs []error
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), runDirPrefix) {
			continue
		}
		path := filepath.Join(binRoot(root), e.Name())
		live, err := runDirLive(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if live {
			continue
		}
		if _, err := os.Stat(filepath.Join(path, keptMarker)); err == nil && !withKept {
			continue
		}
		errs = append(errs, os.RemoveAll(path))
	}
	errs = append(errs, removeIfEmpty(binRoot(root)))
	return errors.Join(errs...)
}

// removeIfEmpty removes dir if it exists and is empty.
func removeIfEmpty(dir string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil || len(entries) > 0 {
		return err
	}
	return os.Remove(dir)
}

// RemoveRunBinaries removes every binary directory this process built; the
// labs that run them must be down, or kept (KeepEnv: their directories
// stay for labctl down). A later lab of the process builds into a new one.
func RemoveRunBinaries(ctx context.Context) error {
	preparedMu.Lock()
	defer preparedMu.Unlock()
	var errs []error
	for root, p := range prepared {
		if err := p.bin.remove(ctx); err != nil {
			errs = append(errs, err)
			continue // still this process's; a later call retries
		}
		delete(prepared, root)
	}
	builtTests.Clear()
	return errors.Join(errs...)
}

// removeStaleBinaries removes, in the checkout at root, the binary
// directories of runs that have ended without removing them, kept labs'
// included: the caller has removed those labs.
func removeStaleBinaries(ctx context.Context, root string) error {
	unlock, err := lockBinRoot(ctx, root)
	if err != nil {
		return err
	}
	defer unlock()
	return sweepBinRoot(root, true)
}

// mainInstalled says the test binary runs its tests through Main.
var mainInstalled atomic.Bool

// Main runs a package's lab tests and then removes the binaries they
// built. Every package with tests that start labs calls it from TestMain,
// as the last thing TestMain does: a lab started without it fails its
// test. A run that dies first (interrupted, killed, a -timeout panic)
// leaves its binaries to the next run's sweep, or to labctl down.
func Main(m *testing.M) {
	mainInstalled.Store(true)
	m.Run() // TestMain may return; the test binary exits with m.Run's code
	if err := RemoveRunBinaries(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "lab: remove binaries:", err)
	}
}
