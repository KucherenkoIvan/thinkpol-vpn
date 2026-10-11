//go:build linux && !android

package worker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent/ipc"
)

// RunDir is the worker's private /run: a fresh tmpfs owned by the worker,
// where netcfg keeps its lock files (netcfg.LockDir) and nothing of the
// node's /run is visible.
const RunDir = "/run/thinkpol"

// deviceNodes are the only device files the worker's root holds: enough for
// a data plane (a TUN, randomness) and nothing else. They are bind-mounted
// from the host, because mknod is not allowed in a user namespace.
var deviceNodes = []string{"/dev/null", "/dev/zero", "/dev/urandom", "/dev/net/tun"}

// netCaps are the capabilities a worker keeps, all confined to its own
// namespaces: NET_ADMIN for its TUN, routes and nftables, NET_RAW for the
// data plane, NET_BIND_SERVICE for its DNS resolver on port 53. SYS_ADMIN
// (needed only for the mounts in sandbox) and everything else are dropped
// before the worker serves.
var netCaps = []uintptr{unix.CAP_NET_ADMIN, unix.CAP_NET_RAW, unix.CAP_NET_BIND_SERVICE}

// sandbox turns the process the supervisor started into a confined one that
// sees only its own space. The supervisor started it as the root of a new
// user namespace (mapped to an unprivileged host uid), with fresh network,
// mount, PID, IPC, UTS and cgroup namespaces, so its capabilities apply only
// to its own namespaces. sandbox then gives it a minimal root filesystem,
// drops SYS_ADMIN, and closes off what it doesn't need.
//
// The worker needs nothing from /proc or /sys once it is serving: it reads
// its uid map here, before pivot_root, and checks itself afterwards with
// prctl and capget; the data plane uses netlink and /dev/net/tun, and the
// supervisor sets the space's network sysctls by entering its namespace, so
// the worker never mounts /proc (which a sandboxed host masks and locks).
func sandbox(init ipc.Init) error {
	if err := checkUserNamespace(init.UID); err != nil {
		return err
	}
	// A hostname in the UTS namespace is cosmetic; don't fail if withheld.
	_ = unix.Sethostname([]byte("worker"))
	if err := pivotToMinimalRoot(); err != nil {
		return err
	}
	if err := os.MkdirAll(RunDir, 0o700); err != nil {
		return err
	}
	if init.PidsMax > 0 {
		lim := unix.Rlimit{Cur: uint64(init.PidsMax), Max: uint64(init.PidsMax)}
		if err := unix.Setrlimit(unix.RLIMIT_NPROC, &lim); err != nil {
			return fmt.Errorf("rlimit nproc: %w", err)
		}
	}
	// no_new_privs and the parent-death signal are per thread, and Go runs
	// goroutines across threads, so set them on every thread of the runtime.
	if err := allThreadsPrctl(unix.PR_SET_NO_NEW_PRIVS, 1); err != nil {
		return fmt.Errorf("no_new_privs: %w", err)
	}
	if err := dropToNetCaps(); err != nil {
		return fmt.Errorf("drop capabilities: %w", err)
	}
	if err := allThreadsPrctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL)); err != nil {
		return fmt.Errorf("parent-death signal: %w", err)
	}
	return checkSandbox()
}

// checkUserNamespace confirms the worker is the root of a new user namespace
// that maps its uid 0 to the host uid the supervisor chose: the escape
// defence rests on it. It reads /proc before pivot_root (the only thing the
// worker takes from /proc).
func checkUserNamespace(hostUID uint32) error {
	b, err := os.ReadFile("/proc/self/uid_map")
	if err != nil {
		return err
	}
	fields := strings.Fields(string(b))
	if len(fields) != 3 || fields[0] != "0" || fields[1] != strconv.FormatUint(uint64(hostUID), 10) {
		return fmt.Errorf("not in the expected user namespace: uid_map %q", strings.TrimSpace(string(b)))
	}
	if os.Getpid() != 1 {
		return errors.New("not PID 1 of its own namespace")
	}
	return nil
}

// pivotToMinimalRoot replaces the worker's root with a fresh tmpfs holding
// only /dev's handful of nodes and empty /run and /tmp. No /proc or /sys is
// mounted (a masked, locked one on a sandboxed host can't be replaced from a
// child user namespace, and the worker needs neither).
func pivotToMinimalRoot() error {
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return fmt.Errorf("make mounts private: %w", err)
	}
	root, err := os.MkdirTemp("", "thinkpol-root")
	if err != nil {
		return err
	}
	if err := unix.Mount("tmpfs", root, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
		return fmt.Errorf("mount new root: %w", err)
	}
	for _, dir := range []string{"dev", "dev/net", "run", "tmp", "oldroot"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			return err
		}
	}
	for _, dev := range deviceNodes {
		target := filepath.Join(root, dev)
		if f, err := os.OpenFile(target, os.O_CREATE, 0o600); err != nil {
			return err
		} else {
			_ = f.Close()
		}
		if err := unix.Mount(dev, target, "", unix.MS_BIND, ""); err != nil {
			return fmt.Errorf("bind %s: %w", dev, err)
		}
	}
	for _, dir := range []string{"run", "tmp"} {
		if err := unix.Mount("tmpfs", filepath.Join(root, dir), "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0755"); err != nil {
			return fmt.Errorf("mount /%s: %w", dir, err)
		}
	}
	if err := unix.PivotRoot(root, filepath.Join(root, "oldroot")); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := unix.Chdir("/"); err != nil {
		return err
	}
	if err := unix.Unmount("/oldroot", unix.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %w", err)
	}
	return os.Remove("/oldroot")
}

// dropToNetCaps keeps only netCaps in every capability set on every thread,
// so the worker loses SYS_ADMIN (which it needed for the mounts) and keeps
// what its data plane needs. Lowering capabilities needs no privilege.
func dropToNetCaps() error {
	var keep uint64
	for _, c := range netCaps {
		keep |= 1 << c
	}
	// The bounding-set drop needs CAP_SETPCAP in the effective set, so do it
	// before the capset below removes SETPCAP along with everything else.
	for c := 0; c <= unix.CAP_LAST_CAP; c++ {
		if keep&(1<<uint(c)) != 0 {
			continue
		}
		if err := allThreadsPrctl(unix.PR_CAPBSET_DROP, uintptr(c)); err != nil {
			return fmt.Errorf("drop capability %d from the bounding set: %w", c, err)
		}
	}
	if err := allThreadsPrctl2(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0); err != nil {
		return fmt.Errorf("clear ambient caps: %w", err)
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	data[0].Effective, data[0].Permitted, data[0].Inheritable = uint32(keep), uint32(keep), 0
	data[1].Effective, data[1].Permitted, data[1].Inheritable = uint32(keep>>32), uint32(keep>>32), 0
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return fmt.Errorf("capset: %w", e)
	}
	return nil
}

func allThreadsPrctl(option int, arg uintptr) error { return allThreadsPrctl2(option, arg, 0) }

// allThreadsPrctl2 runs a two-argument prctl on every OS thread of the
// runtime, for the per-thread settings a worker needs to hold whichever
// thread a goroutine lands on.
func allThreadsPrctl2(option int, arg2, arg3 uintptr) error {
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, uintptr(option), arg2, arg3); e != 0 {
		return e
	}
	return nil
}

// checkSandbox reads back the parts of the sandbox a mistake would silently
// weaken, through prctl and capget (the worker has no /proc).
func checkSandbox() error {
	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || nnp != 1 {
		return fmt.Errorf("no_new_privs is %d (%v)", nnp, err)
	}
	var keep uint64
	for _, c := range netCaps {
		keep |= 1 << c
	}
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: int32(os.Getpid())}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}
	eff := uint64(data[0].Effective) | uint64(data[1].Effective)<<32
	prm := uint64(data[0].Permitted) | uint64(data[1].Permitted)<<32
	if eff != keep || prm != keep {
		return fmt.Errorf("capabilities are eff %016x prm %016x, want %016x", eff, prm, keep)
	}
	if eff&(1<<unix.CAP_SYS_ADMIN) != 0 {
		return errors.New("CAP_SYS_ADMIN still held")
	}
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return fmt.Errorf("no /dev/net/tun in the sandbox: %w", err)
	}
	return nil
}
