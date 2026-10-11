//go:build linux

package nsthread

import (
	"errors"
	"fmt"
	"log/slog"
	"runtime"

	"golang.org/x/sys/unix"
)

// Do runs fn on an OS thread locked to it for the call. fn may move that
// thread into another network namespace and into another mount namespace
// (setns, unshare), and nothing else of the thread's state. Afterwards Do
// moves the thread back into the namespaces it started in and returns fn's
// error, joined with the restore's if that failed.
//
// The thread goes back to the scheduler only if it is exactly as it was.
// Leaving the process's mount namespace unshares the thread's filesystem
// attributes (root, working directory, umask) for good, so a thread whose
// mount namespace moved is never reused, and neither is one that couldn't be
// moved back: its goroutine ends still locked and Go ends the thread with
// it. Except the process's main thread, which Go parks instead of ending:
// that is why the namespaces are restored even for a thread that won't be
// reused, and why a main thread that couldn't be restored is logged.
func Do(fn func() error) error {
	done := make(chan error, 1)
	go func() { done <- run(fn) }()
	return <-done
}

func run(fn func() error) error {
	runtime.LockOSThread()
	h, err := openHome()
	if err != nil {
		runtime.UnlockOSThread()
		return err
	}
	defer h.close()
	err = fn()
	reusable, rerr := h.restore()
	if rerr != nil {
		main := unix.Gettid() == unix.Getpid()
		slog.Error("nsthread: a thread stays in another namespace; it is never reused",
			"err", rerr, "tid", unix.Gettid(), "main_thread", main)
		return errors.Join(err, rerr)
	}
	if reusable {
		runtime.UnlockOSThread()
	}
	return err
}

// home is the namespaces a thread started in.
type home struct {
	dir int // the thread's own /proc/<pid>/task/<tid>/ns
	ns  []homeNS
}

type homeNS struct {
	name string // "net", "mnt"
	kind int    // CLONE_NEW*
	fd   int
	id   nsID
}

type nsID struct{ dev, ino uint64 }

func openHome() (*home, error) {
	// The directory is opened now and read through later, so the current
	// namespaces stay readable after fn moved into a mount namespace without
	// this /proc.
	dir, err := unix.Open("/proc/thread-self/ns", unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("nsthread: %w", err)
	}
	h := &home{dir: dir}
	for _, ns := range []homeNS{{name: "mnt", kind: unix.CLONE_NEWNS}, {name: "net", kind: unix.CLONE_NEWNET}} {
		ns.fd, err = unix.Openat(dir, ns.name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err == nil {
			ns.id, err = fdID(ns.fd)
			if err != nil {
				_ = unix.Close(ns.fd)
			}
		}
		if err != nil {
			h.close()
			return nil, fmt.Errorf("nsthread: own %s namespace: %w", ns.name, err)
		}
		h.ns = append(h.ns, ns)
	}
	return h, nil
}

// restore moves the thread back into every namespace it left. reusable
// reports whether the thread is as it was before fn.
func (h *home) restore() (reusable bool, err error) {
	reusable = true
	var errs []error
	for _, ns := range h.ns {
		moved, err := h.moved(ns)
		if err != nil {
			// Unknown: try to go home anyway. If the thread never left, a
			// mount namespace refuses with EINVAL (its filesystem attributes
			// are still shared), and the thread is kept off the scheduler.
			moved = true
		}
		if !moved {
			continue
		}
		if ns.kind == unix.CLONE_NEWNS {
			reusable = false
		}
		if err := unix.Setns(ns.fd, ns.kind); err != nil {
			errs = append(errs, fmt.Errorf("nsthread: back into the %s namespace: %w", ns.name, err))
			continue
		}
		if moved, err := h.moved(ns); err != nil {
			errs = append(errs, fmt.Errorf("nsthread: %s namespace after setns: %w", ns.name, err))
		} else if moved {
			errs = append(errs, fmt.Errorf("nsthread: still outside the %s namespace after setns", ns.name))
		}
	}
	return reusable, errors.Join(errs...)
}

func (h *home) moved(ns homeNS) (bool, error) {
	var st unix.Stat_t
	if err := unix.Fstatat(h.dir, ns.name, &st, 0); err != nil {
		return false, err
	}
	return statID(&st) != ns.id, nil
}

func (h *home) close() {
	for _, ns := range h.ns {
		_ = unix.Close(ns.fd)
	}
	_ = unix.Close(h.dir)
}

func fdID(fd int) (nsID, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return nsID{}, err
	}
	return statID(&st), nil
}

func statID(st *unix.Stat_t) nsID {
	return nsID{dev: uint64(st.Dev), ino: uint64(st.Ino)} // Dev is 32-bit on some architectures
}
