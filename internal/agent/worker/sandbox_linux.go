//go:build linux && !android

package worker

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
)

// Capabilities are all a worker keeps: NET_ADMIN for its TUN, routes,
// nftables and its namespace's net sysctls (/proc/sys/net, writable with
// NET_ADMIN), NET_BIND_SERVICE for its DNS resolver on port 53. Both count
// only inside the worker's own network namespace, the only one it can
// name: its PID namespace and private /proc hide every other process.
var Capabilities = []int{unix.CAP_NET_ADMIN, unix.CAP_NET_BIND_SERVICE}

// RunDir is the worker's private /run: a fresh tmpfs owned by the worker,
// where netcfg keeps its lock files (netcfg.LockDir) and nothing of the
// node's /run is visible.
const RunDir = "/run/thinkpol"

// sandbox turns the root process the supervisor started into an
// unprivileged one that sees only its own space. The supervisor started it
// in fresh network, mount (already private) and PID namespaces.
func sandbox(init ipc.Init) error {
	if init.UID == 0 || init.GID == 0 {
		return errors.New("refusing to run as root: no worker user")
	}
	// Never propagate a mount out of the worker's mount namespace, whoever
	// set its propagation.
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	// /proc of the worker's PID namespace (only itself) and its network
	// namespace (/proc/net, /proc/sys/net).
	if err := unix.Mount("proc", "/proc", "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount /proc: %w", err)
	}
	// sysfs shows the interfaces of the namespace that mounts it; the node's
	// would show the root namespace's interfaces and their counters.
	if err := unix.Unmount("/sys", unix.MNT_DETACH); err != nil && !errors.Is(err, unix.EINVAL) {
		return fmt.Errorf("unmount the node's /sys: %w", err)
	}
	if err := unix.Mount("sysfs", "/sys", "sysfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC|unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("mount /sys: %w", err)
	}
	if err := unix.Mount("tmpfs", "/run", "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0755,size=1m"); err != nil {
		return fmt.Errorf("mount /run: %w", err)
	}
	if err := os.Mkdir(RunDir, 0o700); err != nil {
		return err
	}
	if err := os.Chown(RunDir, int(init.UID), int(init.GID)); err != nil {
		return err
	}
	if err := dropPrivileges(int(init.UID), int(init.GID), Capabilities); err != nil {
		return fmt.Errorf("drop privileges: %w", err)
	}
	return checkPrivileges(init.UID, Capabilities)
}

// dropPrivileges becomes uid and gid with only keep, for good: the bounding
// set loses everything else, no_new_privs is set. Credentials are per
// thread in Linux, so every step runs on all of the runtime's threads
// (syscall.AllThreadsSyscall, and syscall.Set*id do the same).
func dropPrivileges(uid, gid int, keep []int) error {
	last, err := lastCap()
	if err != nil {
		return err
	}
	kept := uint64(0)
	for _, c := range keep {
		kept |= 1 << c
	}
	// The bounding set first: dropping from it needs CAP_SETPCAP, which
	// goes with it.
	for c := 0; c <= last; c++ {
		if kept&(1<<c) != 0 {
			continue
		}
		if err := allThreadsPrctl(unix.PR_CAPBSET_DROP, uintptr(c)); err != nil {
			return fmt.Errorf("drop capability %d from the bounding set: %w", c, err)
		}
	}
	if err := allThreadsPrctl(unix.PR_SET_KEEPCAPS, 1); err != nil {
		return fmt.Errorf("keep capabilities across setuid: %w", err)
	}
	if err := syscall.Setgroups(nil); err != nil {
		return fmt.Errorf("setgroups: %w", err)
	}
	if err := syscall.Setresgid(gid, gid, gid); err != nil {
		return fmt.Errorf("setresgid: %w", err)
	}
	if err := syscall.Setresuid(uid, uid, uid); err != nil {
		return fmt.Errorf("setresuid: %w", err)
	}
	// Changing user cleared the effective set and kept the permitted one;
	// now permitted and effective become keep, inheritable nothing.
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	data[0].Effective, data[0].Permitted = uint32(kept), uint32(kept)
	data[1].Effective, data[1].Permitted = uint32(kept>>32), uint32(kept>>32)
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return fmt.Errorf("capset: %w", e)
	}
	if err := allThreadsPrctl(unix.PR_SET_KEEPCAPS, 0); err != nil {
		return err
	}
	if err := allThreadsPrctl(unix.PR_SET_NO_NEW_PRIVS, 1); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	// Changing user cleared the parent-death signal the supervisor set.
	// Should the supervisor have died in between, the socket's EOF still
	// ends the worker.
	if err := allThreadsPrctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL)); err != nil {
		return fmt.Errorf("parent-death signal: %w", err)
	}
	return nil
}

func allThreadsPrctl(option int, arg uintptr) error {
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, uintptr(option), arg, 0); e != 0 {
		return e
	}
	return nil
}

func lastCap() (int, error) {
	b, err := os.ReadFile("/proc/sys/kernel/cap_last_cap")
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(strings.TrimSpace(string(b)))
}

// checkPrivileges reads back what the kernel says the worker is now.
func checkPrivileges(uid uint32, keep []int) error {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	want := uint64(0)
	for _, c := range keep {
		want |= 1 << c
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			fields[k] = strings.TrimSpace(v)
		}
	}
	for _, k := range []string{"CapEff", "CapPrm", "CapBnd"} {
		got, err := strconv.ParseUint(fields[k], 16, 64)
		if err != nil || got != want {
			return fmt.Errorf("%s is %s, want %016x", k, fields[k], want)
		}
	}
	for _, k := range []string{"CapInh", "CapAmb"} {
		if got, err := strconv.ParseUint(fields[k], 16, 64); err != nil || got != 0 {
			return fmt.Errorf("%s is %s, want none", k, fields[k])
		}
	}
	if ids := strings.Fields(fields["Uid"]); len(ids) != 4 || ids[0] != fmt.Sprint(uid) || ids[1] != ids[0] || ids[2] != ids[0] || ids[3] != ids[0] {
		return fmt.Errorf("uids are %q, want %d", fields["Uid"], uid)
	}
	if fields["NoNewPrivs"] != "1" {
		return errors.New("no_new_privs is not set")
	}
	return nil
}
