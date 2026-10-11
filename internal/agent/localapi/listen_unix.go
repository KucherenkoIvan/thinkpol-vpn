//go:build unix

package localapi

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"syscall"
)

// Listen opens the local API's socket at path (absolute), in a directory
// of its own that admits only the service's user and the policy's group:
// created 0750 with that group (0700 without one) or, if it exists,
// checked to be exactly that, never changed. Access control is the
// directory's, in place before the socket exists. A socket left behind by
// a service that crashed is removed only when nothing answers on it.
func Listen(path string, p Policy) (net.Listener, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("local API socket %q: want an absolute path", path)
	}
	dir := filepath.Dir(path)
	mode, gid := os.FileMode(0o700), os.Getegid()
	if p.HasGroup {
		mode, gid = 0o750, int(p.Group)
	}
	switch err := os.Mkdir(dir, mode); {
	case errors.Is(err, fs.ErrExist):
		if err := checkDir(dir, mode, gid); err != nil {
			return nil, err
		}
	case err != nil:
		return nil, err
	default:
		// Mkdir is subject to the umask, and the directory takes its
		// parent's group on some systems: set both, then check.
		if err := os.Lchown(dir, -1, gid); err != nil {
			_ = os.Remove(dir)
			return nil, err
		}
		if err := os.Chmod(dir, mode); err != nil {
			_ = os.Remove(dir)
			return nil, err
		}
		if err := checkDir(dir, mode, gid); err != nil {
			return nil, err
		}
	}
	if err := removeStale(path); err != nil {
		return nil, err
	}
	l, err := net.Listen("unix", path)
	if err != nil {
		return nil, err
	}
	// Connecting needs write on the socket too: the group gets it. The
	// directory already admits only the user and the group, so for a
	// moment after Listen the socket may only admit fewer.
	sockMode := os.FileMode(0o600)
	if p.HasGroup {
		sockMode = 0o660
	}
	if err := os.Lchown(path, -1, gid); err != nil {
		_ = l.Close()
		return nil, err
	}
	if err := os.Chmod(path, sockMode); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

// checkDir accepts an existing directory only if this process's user owns
// it, it isn't a symlink, its group is gid and its mode is exactly mode.
func checkDir(dir string, mode os.FileMode, gid int) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || int(st.Uid) != os.Geteuid() || int(st.Gid) != gid || fi.Mode().Perm() != mode {
		return fmt.Errorf("%s: want a directory owned by uid %d, group %d, mode %#o; remove it to have it made", dir, os.Geteuid(), gid, mode)
	}
	return nil
}

// removeStale removes a socket at path that nobody listens on.
func removeStale(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode().Type() != fs.ModeSocket {
		return fmt.Errorf("%s: exists and is not a socket", path)
	}
	conn, err := net.Dial("unix", path)
	switch {
	case err == nil:
		_ = conn.Close()
		return fmt.Errorf("%s: another service is listening", path)
	case errors.Is(err, syscall.ECONNREFUSED):
		return os.Remove(path)
	default:
		return fmt.Errorf("%s: probing the socket left there: %w", path, err)
	}
}
