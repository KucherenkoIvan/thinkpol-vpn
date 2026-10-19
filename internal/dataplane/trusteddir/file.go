//go:build unix

package trusteddir

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// ErrNotRegular: the file is not a regular one (a fifo, a directory).
var ErrNotRegular = errors.New("not a regular file")

// ReadFile reads the regular file name in dir. It never follows a
// symlink (ELOOP) nor blocks on a fifo (ErrNotRegular); a missing file is
// fs.ErrNotExist.
func ReadFile(dir *os.File, name string) ([]byte, error) {
	path := filepath.Join(dir.Name(), name)
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, &os.PathError{Op: "read", Path: path, Err: err}
	}
	return data, nil
}

// WriteFile replaces the file name in dir with data (0600) atomically: a
// new file next to it, synced, then renamed over it. Neither it nor the
// new file is ever reached through a symlink.
func WriteFile(dir *os.File, name string, data []byte) error {
	dirfd := int(dir.Fd())
	tmp := name + ".tmp"
	_ = unix.Unlinkat(dirfd, tmp, 0)
	fd, err := unix.Openat(dirfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return &os.PathError{Op: "create", Path: filepath.Join(dir.Name(), tmp), Err: err}
	}
	f := os.NewFile(uintptr(fd), tmp)
	err = errors.Join(func() error { _, err := f.Write(data); return err }(), f.Sync())
	err = errors.Join(err, f.Close())
	if err == nil {
		err = unix.Renameat(dirfd, tmp, dirfd, name)
	}
	if err != nil {
		_ = unix.Unlinkat(dirfd, tmp, 0)
		return fmt.Errorf("%s: %w", filepath.Join(dir.Name(), name), err)
	}
	return nil
}

// Remove removes the file name in dir; a missing one is no error.
func Remove(dir *os.File, name string) error {
	if err := unix.Unlinkat(int(dir.Fd()), name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return &os.PathError{Op: "remove", Path: filepath.Join(dir.Name(), name), Err: err}
	}
	return nil
}
