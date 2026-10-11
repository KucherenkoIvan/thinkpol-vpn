//go:build linux && !android

package supervisor

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"

	"golang.org/x/sys/unix"
)

// baselineSysctls are the network sysctls every space's namespace gets. The
// supervisor sets them (the worker has no /proc and can't): loose reverse-path
// filtering, so the overlay's and relays' asymmetric paths aren't dropped.
// Egress forwarding is added by TP-014.
var baselineSysctls = map[string]string{
	"net/ipv4/conf/all/rp_filter":     "2",
	"net/ipv4/conf/default/rp_filter": "2",
}

// setNetSysctls sets kv (keys relative to /proc/sys) in the network namespace
// nsFd. It runs on a throwaway OS thread: that thread enters a private mount
// namespace and the target network namespace, mounts a fresh proc there (the
// supervisor is in the initial user namespace, so no masked-proc restriction
// applies), writes the values and exits without unlocking, so the kernel
// discards the thread and nothing of the supervisor's other threads moves.
func setNetSysctls(nsFd int, kv map[string]string) error {
	if len(kv) == 0 {
		return nil
	}
	done := make(chan error, 1)
	go func() {
		runtime.LockOSThread() // never unlocked: the thread is discarded on return
		done <- writeNetSysctls(nsFd, kv)
	}()
	return <-done
}

func writeNetSysctls(nsFd int, kv map[string]string) error {
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return fmt.Errorf("unshare mount namespace: %w", err)
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	if err := unix.Setns(nsFd, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("enter network namespace: %w", err)
	}
	dir, err := os.MkdirTemp("", "thinkpol-netns-proc")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(dir) }()
	// A fresh proc reflects the entered network namespace and is writable
	// regardless of how the node's own /proc is mounted.
	if err := unix.Mount("proc", dir, "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount proc: %w", err)
	}
	defer func() { _ = unix.Unmount(dir, unix.MNT_DETACH) }()
	for _, k := range sortedKeys(kv) {
		if err := os.WriteFile(filepath.Join(dir, "sys", k), []byte(kv[k]), 0); err != nil {
			return fmt.Errorf("sysctl %s: %w", k, err)
		}
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}
