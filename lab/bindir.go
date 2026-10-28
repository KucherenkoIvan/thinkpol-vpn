package lab

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
)

// runBinariesPrefix starts the name of every run's directory in lab/bin.
const runBinariesPrefix = "run-"

// runLockName is the lock file a run holds inside its directory.
const runLockName = ".lock"

// keptMarker, in a run's directory, lists the projects, one per line, of
// the labs that mount it and may be kept (KeepEnv): every lab a run starts
// with KeepEnv set, written before the lab starts. A run that kept a lab,
// or died, leaves the directory behind; no run's sweep removes it, and
// labctl down only once none of those labs is up.
const keptMarker = ".kept"

// binRoot is the checkout's lab/bin, the parent of every run's directory.
func binRoot(root string) string { return filepath.Join(root, "lab", "bin") }

// runBinaries is this process's binary directory, lab/bin/run-*, locked
// while the process holds it.
type runBinaries struct {
	root string // the checkout
	path string
	lock *os.File
	kept atomic.Bool // a lab that mounts it was kept: remove leaves it
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
	// Best effort: a leftover this run can't remove doesn't stop it, and
	// labctl down reports it.
	_ = sweepBinRoot(root, nil)
	if err := os.MkdirAll(binRoot(root), 0o755); err != nil {
		return nil, fmt.Errorf("lab: run directory: %w", err)
	}
	path, err := os.MkdirTemp(binRoot(root), runBinariesPrefix)
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
		err = errors.New("a fresh run directory is locked already")
	}
	if err != nil {
		return nil, errors.Join(fmt.Errorf("lab: run directory: %w", err), os.RemoveAll(path))
	}
	return &runBinaries{root: root, path: path, lock: lock}, nil
}

// recordLab adds project to the labs that mount the directory and may be
// kept (keptMarker). One append per call: parallel tests' lines don't mix.
func (d *runBinaries) recordLab(project string) error {
	f, err := os.OpenFile(filepath.Join(d.path, keptMarker), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("lab: %w", err)
	}
	_, err = f.WriteString(project + "\n")
	if err = errors.Join(err, f.Close()); err != nil {
		return fmt.Errorf("lab: %w", err)
	}
	return nil
}

// keep says a lab that mounts the directory was kept: remove leaves it.
func (d *runBinaries) keep() { d.kept.Store(true) }

// keptBy lists the labs that mount the run directory at path and may be
// kept; none when it has no keptMarker.
func keptBy(path string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(path, keptMarker))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("lab: %w", err)
	}
	return strings.Fields(string(b)), nil
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
	if d.kept.Load() {
		return nil
	}
	if err := errors.Join(os.RemoveAll(d.path), removeIfEmpty(binRoot(d.root))); err != nil {
		return fmt.Errorf("lab: remove binaries: %w", err)
	}
	return nil
}

// runBinariesLive reports whether a live run holds the run directory at
// path. The caller holds lockBinRoot, so a run that has ended can't come
// back.
func runBinariesLive(path string) (bool, error) {
	lock, free, err := tryLockMode(filepath.Join(path, runLockName), true)
	if err != nil {
		return false, fmt.Errorf("lab: %w", err)
	}
	if !free {
		return true, nil
	}
	return false, lock.Close()
}

// sweepBinRoot removes the directories of runs that ended without removing
// them (their lock is free), then lab/bin itself if that leaves it empty.
// A directory kept labs may mount (keptBy) stays: with labUp nil always,
// otherwise while labUp reports one of them up. The caller holds
// lockBinRoot.
func sweepBinRoot(root string, labUp func(project string) bool) error {
	entries, err := os.ReadDir(binRoot(root))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("lab: %w", err)
	}
	var errs []error
	for _, e := range entries {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), runBinariesPrefix) {
			continue
		}
		path := filepath.Join(binRoot(root), e.Name())
		live, err := runBinariesLive(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if live {
			continue
		}
		kept, err := keptBy(path)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if len(kept) > 0 && (labUp == nil || slices.ContainsFunc(kept, labUp)) {
			continue
		}
		if err := os.RemoveAll(path); err != nil {
			errs = append(errs, fmt.Errorf("lab: %w", err))
		}
	}
	if err := removeIfEmpty(binRoot(root)); err != nil {
		errs = append(errs, fmt.Errorf("lab: %w", err))
	}
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
// stay for labctl down). The process forgets each one, removed or not: a
// directory it failed to remove is left, unlocked, to a later sweep, and a
// later lab of the process builds into a new one.
func RemoveRunBinaries(ctx context.Context) error {
	preparedMu.Lock()
	defer preparedMu.Unlock()
	var errs []error
	for root, p := range prepared {
		errs = append(errs, p.bin.remove(ctx))
		delete(prepared, root)
	}
	builtTests.Clear()
	return errors.Join(errs...)
}

// removeStaleBinaries removes, in the checkout at root, the binary
// directories of runs that have ended without removing them, and those of
// kept labs once none of their labs is up (labUp).
func removeStaleBinaries(ctx context.Context, root string, labUp func(project string) bool) error {
	unlock, err := lockBinRoot(ctx, root)
	if err != nil {
		return err
	}
	defer unlock()
	return sweepBinRoot(root, labUp)
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
