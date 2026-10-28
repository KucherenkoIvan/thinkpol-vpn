package lab

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// Every run (process) builds its binaries into a directory of its own,
// lab/bin/run-*, which its labs mount at BinDir: two runs from one checkout
// never rebuild a binary the other's containers have open or are about to
// exec. A run holds the lock file inside its directory until it removes
// the directory; a directory whose lock nobody holds is a run that ended
// without removing it (killed, or a test binary's -timeout panic), and the
// next run, or labctl down, removes it.

// runDirPrefix starts the name of every run's directory in lab/bin.
const runDirPrefix = "run-"

// runLockName is the lock file a run holds inside its directory.
const runLockName = ".lock"

// legacyBinEntries are what lab/bin held before runs had directories of
// their own; nothing uses them any more.
var legacyBinEntries = []string{"thinkpol", "labdns", "censord", "tests"}

// binRoot is the checkout's lab/bin, the parent of every run's directory.
func binRoot(root string) string { return filepath.Join(root, "lab", "bin") }

// runDir is a run's binary directory, held while the run lasts.
type runDir struct {
	path string
	lock *os.File
}

// lockBinRoot serializes creating, sweeping and removing run directories of
// one checkout, so a sweep never takes a directory between its creation and
// its lock, and lab/bin is never removed under a run creating its
// directory. The lock lives with the host-wide ones, not in lab/bin, which
// goes once empty.
func lockBinRoot(ctx context.Context, root string) (func(), error) {
	dir, err := lockDir()
	if err != nil {
		return nil, err
	}
	return waitLock(ctx, "the lab/bin lock", filepath.Join(dir, "bin-"+shortHash(root)+".lock"))
}

// newRunDir sweeps away what ended runs left in lab/bin and creates this
// run's directory, locked.
func newRunDir(ctx context.Context, root string) (*runDir, error) {
	unlock, err := lockBinRoot(ctx, root)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := sweepBinRoot(root); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(binRoot(root), 0o755); err != nil {
		return nil, err
	}
	path, err := os.MkdirTemp(binRoot(root), runDirPrefix)
	if err != nil {
		return nil, err
	}
	// MkdirTemp makes it 0700; the nodes' root reads it through the mount,
	// which on Linux hosts keeps the owner.
	if err := os.Chmod(path, 0o755); err != nil {
		return nil, errors.Join(err, os.RemoveAll(path))
	}
	lock, ok, err := tryLockMode(filepath.Join(path, runLockName), true)
	if err == nil && !ok {
		err = errors.New("lab: a fresh run directory is locked already")
	}
	if err != nil {
		return nil, errors.Join(err, os.RemoveAll(path))
	}
	return &runDir{path: path, lock: lock}, nil
}

// remove deletes the run's directory, and lab/bin when no other run has
// one there.
func (d *runDir) remove(ctx context.Context, root string) error {
	unlock, err := lockBinRoot(ctx, root)
	if err != nil {
		return err
	}
	defer unlock()
	err = os.RemoveAll(d.path)
	_ = d.lock.Close()
	return errors.Join(err, removeIfEmpty(binRoot(root)))
}

// sweepBinRoot removes the directories of runs that ended without removing
// them (their lock is free) and what lab/bin held before runs had
// directories, then lab/bin itself if that leaves it empty. The caller
// holds lockBinRoot.
func sweepBinRoot(root string) error {
	entries, err := os.ReadDir(binRoot(root))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range entries {
		path := filepath.Join(binRoot(root), e.Name())
		switch {
		case e.IsDir() && strings.HasPrefix(e.Name(), runDirPrefix):
			lock, free, err := tryLockMode(filepath.Join(path, runLockName), true)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if !free {
				continue // a live run's
			}
			errs = append(errs, os.RemoveAll(path))
			_ = lock.Close()
		case isLegacyBinEntry(e.Name()):
			errs = append(errs, os.RemoveAll(path))
		}
	}
	errs = append(errs, removeIfEmpty(binRoot(root)))
	return errors.Join(errs...)
}

func isLegacyBinEntry(name string) bool {
	for _, l := range legacyBinEntries {
		if name == l || strings.HasPrefix(name, "."+l+".") { // goBuild's temporary files
			return true
		}
	}
	return false
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

// RemoveBinaries removes the binary directory this process built for the
// labs of the checkout at root, if it has one; its labs must be down. A
// later lab of the process builds into a new one.
func RemoveBinaries(ctx context.Context, root string) error {
	preparedMu.Lock()
	defer preparedMu.Unlock()
	p, ok := prepared[root]
	if !ok {
		return nil
	}
	delete(prepared, root)
	return p.bin.remove(ctx, root)
}

// RemoveStaleBinaries removes, in the checkout at root, the binary
// directories of runs that have ended without removing them.
func RemoveStaleBinaries(ctx context.Context, root string) error {
	unlock, err := lockBinRoot(ctx, root)
	if err != nil {
		return err
	}
	defer unlock()
	return sweepBinRoot(root)
}

// Main runs a package's lab tests (call it from TestMain) and removes the
// binaries they built when they end, or when the run is interrupted
// (SIGINT, SIGTERM): the test binary would otherwise exit without running
// anything more.
func Main(m *testing.M) {
	removeAll := func() {
		ctx := context.Background()
		root, err := Root()
		if err == nil {
			err = RemoveBinaries(ctx, root)
		}
		if err != nil {
			_, _ = os.Stderr.WriteString("lab: remove binaries: " + err.Error() + "\n")
		}
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		removeAll()
		os.Exit(1)
	}()
	code := m.Run()
	signal.Stop(sig)
	removeAll()
	os.Exit(code)
}
