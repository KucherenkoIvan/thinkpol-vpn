//go:build linux || darwin

package agent

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A start takes the host's agent lock once and holds it while the node
// runs. With the real lock (a file of the test's), taking it again
// anywhere on the way (as `run` once did, after Adapters) fails the start.
func TestAStartTakesTheHostLockOnce(t *testing.T) {
	path := filepath.Join(tempDir(t), "agent.lock")
	cleaned := make(chan struct{}, 1)
	// The lock is real here (a file of the test's); DNS restore is a
	// fake.
	plat := testPlatform()
	plat.LockHost = func() (func(), error) { return lockHostAt(path) }
	plat.RestoreDNS = func() error { cleaned <- struct{}{}; return nil }

	s := newTestSpace(t)
	cfg := testConfig(s.stateDir(t, s.b, 1))
	cfg.Connect = false // nothing of a data plane on the host
	logs, err := NewLogs("info", io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	n, err := Prepare(cfg, logs, plat)
	if err != nil {
		t.Fatal(err)
	}
	adapters, err := n.Adapters(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	for _, a := range adapters {
		if a.Name == "node" {
			go func() { done <- a.Run(ctx) }()
		}
	}
	select {
	case <-cleaned:
	case err := <-done:
		t.Fatalf("the node stopped at its start: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("the node didn't get to its start-up cleanups")
	}
	eventually(t, func() bool { return n.Status().MapVersion == 1 })
	select {
	case err := <-done:
		t.Fatalf("the node stopped: %v", err)
	default:
	}
	if _, err := lockHostAt(path); !errors.Is(err, errAnotherAgent) {
		t.Errorf("a second agent while the node runs: %v", err)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the node's stop: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the node didn't stop")
	}
	unlock, err := lockHostAt(path)
	if err != nil {
		t.Fatalf("the lock after the node stopped: %v", err)
	}
	unlock()
}

func TestOneAgentHoldsTheHostLock(t *testing.T) {
	path := filepath.Join(tempDir(t), "thinkpol", "agent.lock")
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
	path := filepath.Join(tempDir(t), "agent.lock")
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
		dir := filepath.Join(tempDir(t), "thinkpol")
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
		base := tempDir(t)
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
		dir := tempDir(t)
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
