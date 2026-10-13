//go:build linux || darwin

package agent

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestOneAgentHoldsTheHostLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "thinkpol", "agent.lock")
	unlock, err := lockHostAt(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Dir(path)); err != nil || fi.Mode().Perm() != 0o700 {
		t.Fatalf("the lock's directory: %v %v", fi, err)
	}
	_, err = lockHostAt(path)
	if !errors.Is(err, errAnotherAgent) || !strings.Contains(err.Error(), path) {
		t.Fatalf("a second lock: %v", err)
	}
	unlock()
	unlock, err = lockHostAt(path)
	if err != nil {
		t.Fatalf("the lock after its release: %v", err)
	}
	unlock()
}

func TestTheHostLockOutlivesNoAgent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.lock")
	unlock, err := lockHostAt(path)
	if err != nil {
		t.Fatal(err)
	}
	// What the agent starts (a server's workers) doesn't inherit it.
	child := exec.Command("sleep", "30")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	unlock()
	unlock, err = lockHostAt(path)
	if err != nil {
		t.Fatalf("held by the agent's child: %v", err)
	}
	unlock()
}

func TestTheHostLockRefusesAPlaceOthersControl(t *testing.T) {
	t.Run("a directory others can write to", func(t *testing.T) {
		dir := filepath.Join(t.TempDir(), "thinkpol")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		if _, err := lockHostAt(filepath.Join(dir, "agent.lock")); err == nil || errors.Is(err, errAnotherAgent) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a symlinked directory", func(t *testing.T) {
		base := t.TempDir()
		if err := os.Mkdir(filepath.Join(base, "real"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("real", filepath.Join(base, "thinkpol")); err != nil {
			t.Fatal(err)
		}
		if _, err := lockHostAt(filepath.Join(base, "thinkpol", "agent.lock")); err == nil || errors.Is(err, errAnotherAgent) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("a symlinked lock file", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "elsewhere")
		if err := os.Symlink(target, filepath.Join(dir, "agent.lock")); err != nil {
			t.Fatal(err)
		}
		if _, err := lockHostAt(filepath.Join(dir, "agent.lock")); err == nil || errors.Is(err, errAnotherAgent) {
			t.Fatalf("got %v", err)
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("the symlink's target was created: %v", err)
		}
	})
}
