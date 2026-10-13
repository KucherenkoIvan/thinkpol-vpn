package agent

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// hostLockPath is the node agent's lock on macOS, where the agent changes
// host-wide state outside any namespace (routes, the resolver
// configuration): one agent per host.
const hostLockPath = "/var/run/thinkpol/agent.lock"

// errAnotherAgent: another node agent runs on this host.
var errAnotherAgent = errors.New("another thinkpol node agent runs on this host")

// hostLock takes the host's agent lock (an exclusive flock, released when
// the process dies) and returns its release.
func hostLock() (func(), error) {
	dir := filepath.Dir(hostLockPath)
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
	fd, err := unix.Open(hostLockPath, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, errAnotherAgent
		}
		return nil, err
	}
	return func() { _ = unix.Close(fd) }, nil
}
