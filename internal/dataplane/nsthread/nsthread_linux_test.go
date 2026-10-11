//go:build linux

package nsthread_test

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/nsthread"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/nsthread/nsthreadtest"
)

func needsLab(t *testing.T) {
	t.Helper()
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
}

// throwawayNetns adds a named network namespace for the test and returns
// it open.
func throwawayNetns(t *testing.T) *os.File {
	t.Helper()
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	name := "nsthread-" + hex.EncodeToString(b)
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v: %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", name).Run() })
	f, err := os.Open("/run/netns/" + name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return f
}

func threadNS(kind string) string {
	l, _ := os.Readlink("/proc/thread-self/ns/" + kind)
	return l
}

// Many round trips into another network and mount namespace, one after
// another and then at once, leave every thread of the process, the main one
// included, in its own.
func TestDoLeavesNoThreadBehind(t *testing.T) {
	needsLab(t)
	target := throwawayNetns(t)
	want := threadNS("net")
	roundTrip := func(enterMount bool) error {
		return nsthread.Do(func() error {
			if enterMount {
				if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
					return err
				}
				if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
					return err
				}
			}
			if err := unix.Setns(int(target.Fd()), unix.CLONE_NEWNET); err != nil {
				return err
			}
			if threadNS("net") == want {
				return errors.New("setns didn't move the thread")
			}
			return nil
		})
	}
	for i := range 100 {
		if err := roundTrip(i%2 == 0); err != nil {
			t.Fatal(err)
		}
	}
	var wg sync.WaitGroup
	errs := make(chan error, 100)
	for i := range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- roundTrip(i%2 == 0)
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	nsthreadtest.CheckThreadsHome(t)
}

// fn's error comes back, and a thread that failed before moving is fine.
func TestDoReturnsTheError(t *testing.T) {
	needsLab(t)
	boom := errors.New("boom")
	for range 50 {
		if err := nsthread.Do(func() error { return boom }); !errors.Is(err, boom) {
			t.Fatalf("got %v, want %v", err, boom)
		}
	}
	err := nsthread.Do(func() error {
		if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
			return err
		}
		return boom
	})
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want %v", err, boom)
	}
	nsthreadtest.CheckThreadsHome(t)
}
