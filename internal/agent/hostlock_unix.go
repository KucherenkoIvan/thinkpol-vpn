//go:build linux || darwin

package agent

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// errAnotherAgent: another node agent holds the host's agent lock.
var errAnotherAgent = errors.New("another thinkpol agent is running on this host")

// HostLock takes the host's agent lock: an exclusive flock on the host's
// lock path, held until the release or the process dies. A node agent
// changes host-wide state outside any namespace (routes, the resolver
// configuration), and its start-time cleanups would undo a running
// agent's: one agent per host.
func HostLock() (func(), error) { return lockHostAt(hostLockPath) }

// lockHostAt takes an exclusive flock on path, held until the release or
// the process's end. Its directory is made if missing and, with every
// directory above it, must be this user's (or root's) and writable by no
// one else, so no one can rename it away from under a running agent's
// lock and have the next agent lock a fresh file. The descriptor is
// close-on-exec, so no process the agent starts (a server's workers) holds
// the lock after it.
func lockHostAt(path string) (func(), error) {
	dir, err := trusteddir.Make(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer func() { _ = dir.Close() }()
	f, err := trusteddir.Lock(dir, filepath.Base(path))
	if errors.Is(err, trusteddir.ErrLocked) {
		return nil, fmt.Errorf("%w (it holds %s)", errAnotherAgent, path)
	}
	if err != nil {
		return nil, err
	}
	return func() { _ = f.Close() }, nil
}
