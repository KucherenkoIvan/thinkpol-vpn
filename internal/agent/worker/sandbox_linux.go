//go:build linux && !android

package worker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

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

// sandbox turns the process the supervisor started into a confined one that
// sees only its own space. The supervisor started it as the root of a new
// user namespace (mapped to an unprivileged host uid), with fresh network,
// mount, PID, IPC, UTS and cgroup namespaces, so its capabilities apply only
// to its own namespaces. sandbox then gives it a minimal root filesystem and
// closes off what it doesn't need.
func sandbox(init ipc.Init) error {
	if err := checkUserNamespace(init.UID); err != nil {
		return err
	}
	// A hostname in the UTS namespace is cosmetic; don't fail the worker if
	// the kernel withholds it.
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
	if err := allThreadsPrctl(unix.PR_SET_PDEATHSIG, uintptr(unix.SIGKILL)); err != nil {
		return fmt.Errorf("parent-death signal: %w", err)
	}
	return checkSandbox()
}

// checkUserNamespace confirms the worker is the root of a new user namespace
// that maps its uid 0 to the host uid the supervisor chose: the escape
// defence rests on it.
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
// only /dev's handful of nodes, a fresh /proc, a read-only /sys, and empty
// /run and /tmp.
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
	for _, dir := range []string{"dev", "dev/net", "proc", "sys", "run", "tmp", "oldroot"} {
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
	// In a user namespace a fresh proc or sysfs mount is allowed only when a
	// fully-visible one already exists. A sandbox or container runtime
	// (Docker in the lab) masks parts of /proc and /sys with submounts,
	// which hides them; unmount those in this private mount namespace first,
	// so the fresh mounts are permitted. On an unmasked host it is a no-op.
	if err := unmaskSubmounts("/proc"); err != nil {
		return err
	}
	if err := unmaskSubmounts("/sys"); err != nil {
		return err
	}
	if err := unix.Mount("proc", filepath.Join(root, "proc"), "proc", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return fmt.Errorf("mount /proc (a masked or locked /proc on the host prevents a nested one): %w", err)
	}
	if err := unix.Mount("sysfs", filepath.Join(root, "sys"), "sysfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC|unix.MS_RDONLY, ""); err != nil {
		return fmt.Errorf("mount /sys: %w", err)
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

// allThreadsPrctl runs a prctl on every OS thread of the runtime, for the
// per-thread settings (no_new_privs, the parent-death signal) a worker needs
// to hold whichever thread a goroutine lands on.
func allThreadsPrctl(option int, arg uintptr) error {
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, uintptr(option), arg, 0); e != 0 {
		return e
	}
	return nil
}

// unmaskSubmounts detaches every mount strictly under dir in this mount
// namespace, deepest first, so dir's own mount becomes fully visible.
func unmaskSubmounts(dir string) error {
	b, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	var points []string
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		mp := f[4]
		if strings.HasPrefix(mp, dir+"/") {
			points = append(points, mp)
		}
	}
	// Deepest first, so a parent isn't unmounted before its children.
	slices.SortFunc(points, func(a, b string) int { return len(b) - len(a) })
	for _, mp := range points {
		if err := unix.Unmount(mp, unix.MNT_DETACH); err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("unmask %s: %w", mp, err)
		}
	}
	return nil
}

// checkSandbox reads back the parts of the sandbox a mistake would silently
// weaken.
func checkSandbox() error {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok {
			fields[k] = strings.TrimSpace(v)
		}
	}
	if fields["NoNewPrivs"] != "1" {
		return errors.New("no_new_privs is not set")
	}
	// A TUN is the data plane's; confirm the device node is there.
	if _, err := os.Stat("/dev/net/tun"); err != nil {
		return fmt.Errorf("no /dev/net/tun in the sandbox: %w", err)
	}
	return nil
}
