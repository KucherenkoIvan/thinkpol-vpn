//go:build linux || darwin

package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// errAnotherAgent: another node agent holds the host's agent lock.
var errAnotherAgent = errors.New("another thinkpol agent is running on this host")

// hostLock takes the host's agent lock (hostLockPath) and returns its
// release. A node agent changes host-wide state outside any namespace
// (routes, the resolver configuration), and its start-time cleanups would
// undo a running agent's: one agent per host.
func hostLock() (func(), error) { return lockHostAt(hostLockPath) }

// lockHostAt takes an exclusive flock on path, held until the release or
// the process's end. The descriptor is close-on-exec, so no process the
// agent starts (a server's workers) holds the lock after it.
func lockHostAt(path string) (func(), error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); !fi.IsDir() || !ok || int(st.Uid) != os.Geteuid() || fi.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("%s: want a directory of uid %d that no one else can write to", dir, os.Geteuid())
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%w (it holds %s)", errAnotherAgent, path)
		}
		return nil, err
	}
	return func() { _ = unix.Close(fd) }, nil
}
