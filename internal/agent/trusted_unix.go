//go:build unix

package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// trustedDir is a directory whose files a node may believe: owned by the
// node's user (or root), not a symlink, and writable by nobody else. Files
// are opened relative to the directory's descriptor, without following a
// symlink and without blocking on a FIFO, and checked on the open
// descriptor, so nothing can be swapped between the check and the read.
type trustedDir struct {
	f    *os.File
	path string
}

func openTrustedDir(path string) (*trustedDir, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
			return nil, fmt.Errorf("%s: not a directory (a symlink is refused)", path)
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	fi, err := f.Stat()
	if err == nil {
		err = trusted(path, fi, false)
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return &trustedDir{f: f, path: path}, nil
}

func (d *trustedDir) Close() error { return d.f.Close() }

// names lists the directory.
func (d *trustedDir) names() ([]string, error) {
	return d.f.Readdirnames(-1)
}

// read reads the regular file name in the directory, at most limit bytes
// (more is an error). A private file must not be readable by others.
func (d *trustedDir) read(name string, private bool, limit int64) ([]byte, os.FileInfo, error) {
	path := d.path + string(os.PathSeparator) + name
	fd, err := unix.Openat(int(d.f.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, unix.ELOOP) {
			return nil, nil, fmt.Errorf("%s: a symlink is refused", path)
		}
		return nil, nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("%s: not a regular file", path)
	}
	if err := trusted(path, fi, private); err != nil {
		return nil, nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, nil, err
	}
	if int64(len(b)) > limit {
		return nil, nil, fmt.Errorf("%s: larger than %d bytes", path, limit)
	}
	return b, fi, nil
}

// trusted checks an open file's owner and mode.
func trusted(path string, fi os.FileInfo, private bool) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: no owner", path)
	}
	if uid := int(st.Uid); uid != 0 && uid != os.Geteuid() {
		return fmt.Errorf("%s: owned by uid %d, not by this user or root", path, uid)
	}
	perm := fi.Mode().Perm()
	if private && perm&0o077 != 0 {
		return fmt.Errorf("%s: mode %04o lets others read the node's private keys; chmod 600 it", path, perm)
	}
	if perm&0o022 != 0 {
		return fmt.Errorf("%s: mode %04o lets others change it; chmod go-w it", path, perm)
	}
	return nil
}
