//go:build unix

package localapi

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// MaxConns bounds the local API's open connections: the CLI and a tray
// app need a handful, and a local client opening more only waits.
const MaxConns = 32

// LockFile, next to the socket, is held while a service serves it, so
// two services starting at once can't both take the socket over.
const LockFile = "api.lock"

// Listen opens the local API's socket at path (absolute), in a directory
// of its own that admits only the service's user and the policy's group:
// 0750 with that group, 0700 without one. Access control is the
// directory's, in place before the socket exists. The directory's parent
// must be root's (or the service user's) and writable by no one else; the
// directory is created, or, when it is a real directory of the service's
// user left from an earlier run, given the right group and mode through
// its own descriptor. Symlinks and directories of other users are refused.
// A socket left behind by a service that crashed is removed only when
// nothing answers on it, under LockFile.
func Listen(path string, p Policy) (net.Listener, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("local API socket %q: want an absolute path", path)
	}
	dir := filepath.Dir(path)
	if err := checkParent(filepath.Dir(dir)); err != nil {
		return nil, err
	}
	mode, gid := os.FileMode(0o700), os.Getegid()
	if p.HasGroup {
		mode, gid = 0o750, int(p.Group)
	}
	if err := os.Mkdir(dir, mode); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	if err := ownDir(dir, mode, gid); err != nil {
		return nil, err
	}
	lock, err := lockDir(dir)
	if err != nil {
		return nil, err
	}
	l, err := listen(path, p, gid)
	if err != nil {
		_ = lock.Close()
		return nil, err
	}
	return &limitListener{UnixListener: l, lock: lock, slots: make(chan struct{}, MaxConns), done: make(chan struct{})}, nil
}

func listen(path string, p Policy, gid int) (*net.UnixListener, error) {
	if err := removeStale(path); err != nil {
		return nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
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

// checkParent accepts the socket directory's parent only if root or the
// service's user owns it and no one else may write to it, so no one else
// can swap the socket's directory.
func checkParent(parent string) error {
	fi, err := os.Stat(parent)
	if err != nil {
		return err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || (st.Uid != 0 && int(st.Uid) != os.Geteuid()) || fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s: the local API's directory must be in a directory of root's (or uid %d's) that no one else can write to", parent, os.Geteuid())
	}
	return nil
}

// ownDir checks dir on its own descriptor (not a symlink, a directory of
// the service's user) and gives it gid and mode if it lacks them.
func ownDir(dir string, mode os.FileMode, gid int) error {
	fd, err := unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("%s: want a directory, not a symlink: %w", dir, err)
	}
	defer func() { _ = unix.Close(fd) }()
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return err
	}
	if int(st.Uid) != os.Geteuid() {
		return fmt.Errorf("%s: owned by uid %d, not the service's %d; remove it to have it made", dir, st.Uid, os.Geteuid())
	}
	if int(st.Gid) != gid {
		if err := unix.Fchown(fd, -1, gid); err != nil {
			return fmt.Errorf("%s: %w", dir, err)
		}
	}
	if os.FileMode(st.Mode).Perm() != mode || st.Mode&(unix.S_ISUID|unix.S_ISGID|unix.S_ISVTX) != 0 {
		if err := unix.Fchmod(fd, uint32(mode)); err != nil {
			return fmt.Errorf("%s: %w", dir, err)
		}
	}
	return nil
}

// lockDir takes LockFile in dir, or fails if another service holds it.
func lockDir(dir string) (*os.File, error) {
	path := filepath.Join(dir, LockFile)
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%s: another service is serving the local API", dir)
		}
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
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

// limitListener holds at most cap(slots) connections open: Accept waits
// for one to close. Its connections stay *net.UnixConn underneath (for
// their peer credentials). Closing it releases the lock.
type limitListener struct {
	*net.UnixListener
	lock  *os.File
	slots chan struct{}
	done  chan struct{}
	once  sync.Once
}

func (l *limitListener) Accept() (net.Conn, error) {
	select {
	case l.slots <- struct{}{}:
	case <-l.done:
		return nil, net.ErrClosed
	}
	c, err := l.AcceptUnix()
	if err != nil {
		<-l.slots
		return nil, err
	}
	return &limitedConn{UnixConn: c, release: func() { <-l.slots }}, nil
}

func (l *limitListener) Close() error {
	err := l.UnixListener.Close()
	l.once.Do(func() {
		close(l.done)
		_ = l.lock.Close()
	})
	return err
}

type limitedConn struct {
	*net.UnixConn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.UnixConn.Close()
	c.once.Do(c.release)
	return err
}
