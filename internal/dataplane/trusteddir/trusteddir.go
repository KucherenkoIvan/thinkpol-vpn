//go:build unix

// Package trusteddir opens directories whose contents a process may
// believe: the directory and every directory on its path are owned by the
// process's user (or root), none is a symlink, and none is writable by
// anyone else. The path is walked from / one component at a time with
// openat(O_NOFOLLOW), each checked on its open descriptor, so nothing on
// the way can be swapped for a symlink between the check and the use, and
// no one else can rename a directory on the way while it is used. An
// ancestor writable by others is passed through only when it is sticky
// (like /tmp): there others can add entries but not rename or remove ours,
// and a foreign entry on the path fails the owner check. The directory
// itself is never sticky or writable by others. Whatever is done inside it
// is done relative to its descriptor.
package trusteddir

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrLocked: another process holds the lock.
var ErrLocked = errors.New("locked by another process")

// Open opens the directory at path, checked on the way.
func Open(path string) (*os.File, error) { return walk(path, false) }

// Make is Open, making each missing directory on the way first (0700, as
// the umask allows), checked like the rest.
func Make(path string) (*os.File, error) { return walk(path, true) }

func walk(path string, create bool) (*os.File, error) {
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
		if err := check(fd, walked, last); err != nil {
			_ = unix.Close(fd)
			return nil, err
		}
		if last {
			break
		}
		walked = filepath.Join(walked, components[i])
		next, err := openDir(fd, components[i])
		if create && errors.Is(err, unix.ENOENT) {
			if err = unix.Mkdirat(fd, components[i], 0o700); err == nil || errors.Is(err, unix.EEXIST) {
				next, err = openDir(fd, components[i])
			}
		}
		_ = unix.Close(fd)
		if err != nil {
			if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.ENOTDIR) {
				return nil, fmt.Errorf("%s: not a directory (a symlink is refused)", walked)
			}
			return nil, &os.PathError{Op: "open", Path: walked, Err: err}
		}
		fd = next
	}
	return os.NewFile(uintptr(fd), abs), nil
}

func openDir(dirfd int, name string) (int, error) {
	return unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
}

// check checks one directory of the walk.
func check(fd int, path string, last bool) error {
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

// Lock takes an exclusive flock on the regular file name in dir (made,
// 0600, if missing; never a symlink), held until the returned file is
// closed or the process ends; ErrLocked if another process holds it. The
// descriptor is close-on-exec, so no process this one starts holds the
// lock after it.
func Lock(dir *os.File, name string) (*os.File, error) {
	f, err := openRegular(dir, name, unix.O_RDWR|unix.O_CREAT, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, fmt.Errorf("%s: %w", f.Name(), ErrLocked)
		}
		return nil, &os.PathError{Op: "flock", Path: f.Name(), Err: err}
	}
	return f, nil
}
