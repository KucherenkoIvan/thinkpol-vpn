//go:build unix

package agent

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// trustedDir is a directory whose files a node may believe: it and every
// directory on its path are owned by the node's user (or root), none is a
// symlink, and none is writable by anyone else. The path is walked from /
// one component at a time with openat(O_NOFOLLOW), each checked on its open
// descriptor, so nothing on the way can be swapped for a symlink between
// the check and the use. An ancestor writable by others is passed through
// only when it is sticky (like /tmp): there others can add entries but not
// rename or remove ours, and a foreign entry on the path fails the owner
// check. The directory itself is never sticky or writable by others.
// Files are opened relative to its descriptor, without following a symlink
// and without blocking on a FIFO, and checked on the open descriptor.
type trustedDir struct {
	f    *os.File
	path string
}

func openTrustedDir(path string) (*trustedDir, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: "/", Err: err}
	}
	components := strings.Split(strings.TrimPrefix(abs, "/"), "/")
	if abs == "/" {
		components = nil
	}
	walked := "/"
	for i := 0; ; i++ {
		last := i == len(components)
		if err := trustedDirFD(fd, walked, last); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		if last {
			break
		}
		walked = filepath.Join(walked, components[i])
		next, err := unix.Openat(fd, components[i], unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
				return nil, fmt.Errorf("%s: not a directory (a symlink is refused)", walked)
			}
			return nil, &os.PathError{Op: "open", Path: walked, Err: err}
		}
		fd = next
	}
	return &trustedDir{f: os.NewFile(uintptr(fd), abs), path: abs}, nil
}

// trustedDirFD checks one directory of the walk.
func trustedDirFD(fd int, path string, last bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if uid := int(st.Uid); uid != 0 && uid != os.Geteuid() {
		return fmt.Errorf("%s: owned by uid %d, not by this user or root", path, uid)
	}
	perm := os.FileMode(st.Mode) & os.ModePerm
	if perm&0o022 != 0 && (last || st.Mode&unix.S_ISVTX == 0) {
		return fmt.Errorf("%s: mode %04o lets others change it; chmod go-w it", path, perm)
	}
	return nil
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

// write replaces the file name in the directory with data, atomically: a
// new file (mode perm, the service's own) is written, synced and renamed
// over it, and the directory synced, so a crash leaves the old file or the
// new one, never a part.
func (d *trustedDir) write(name string, data []byte, perm os.FileMode) error {
	tmp := "." + name + ".new"
	dirfd := int(d.f.Fd())
	_ = unix.Unlinkat(dirfd, tmp, 0)
	fd, err := unix.Openat(dirfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, uint32(perm))
	if err != nil {
		return &os.PathError{Op: "create", Path: d.path + string(os.PathSeparator) + tmp, Err: err}
	}
	f := os.NewFile(uintptr(fd), tmp)
	err = errors.Join(func() error { _, err := f.Write(data); return err }(), f.Chmod(perm), f.Sync())
	err = errors.Join(err, f.Close())
	if err == nil {
		err = unix.Renameat(dirfd, tmp, dirfd, name)
	}
	if err != nil {
		_ = unix.Unlinkat(dirfd, tmp, 0)
		return fmt.Errorf("%s: %w", d.path+string(os.PathSeparator)+name, err)
	}
	return d.f.Sync()
}
