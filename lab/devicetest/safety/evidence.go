//go:build darwin || linux

package safety

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// evidence is a run's evidence folder as root writes into it on its
// owner's behalf: opened once, checked as the owner's
// (trusteddir.OpenOwnedBy), every file made relative to it, never through
// a symlink nor over an existing file, and handed to the owner. Root never
// removes anything in it: captures are kept.
type evidence struct {
	dir      *os.File
	uid, gid int
}

// openEvidence opens the folder at path, which must be uid's.
func openEvidence(path string, uid, gid int) (*evidence, error) {
	d, err := trusteddir.OpenOwnedBy(path, uid)
	if err != nil {
		return nil, err
	}
	return &evidence{dir: d, uid: uid, gid: gid}, nil
}

// path is the folder's path.
func (e *evidence) path() string { return e.dir.Name() }

// close closes the folder.
func (e *evidence) close() error { return e.dir.Close() }

var relPath = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$`)

// create makes the file rel (a relative path, its directories made as
// needed), which must not exist yet, owned by the folder's owner.
func (e *evidence) create(rel string) (*os.File, error) {
	if !relPath.MatchString(rel) || strings.Contains(rel, "..") {
		return nil, fmt.Errorf("evidence: bad name %q", rel)
	}
	dirfd, err := e.mkdirs(filepath.Dir(rel))
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(dirfd) }()
	name := filepath.Base(rel)
	fd, err := unix.Openat(dirfd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: filepath.Join(e.path(), rel), Err: err}
	}
	if err := unix.Fchown(fd, e.uid, e.gid); err != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "chown", Path: filepath.Join(e.path(), rel), Err: err}
	}
	return os.NewFile(uintptr(fd), filepath.Join(e.path(), rel)), nil
}

// writeFile creates rel with data.
func (e *evidence) writeFile(rel string, data []byte) error {
	f, err := e.create(rel)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return errors.Join(err, f.Close())
}

// mkdirs opens dir under the folder, making what is missing (0700, the
// owner's), one component at a time, never through a symlink.
func (e *evidence) mkdirs(dir string) (int, error) {
	fd, err := unix.Dup(int(e.dir.Fd()))
	if err != nil {
		return -1, err
	}
	if dir == "." {
		return fd, nil
	}
	for _, c := range strings.Split(dir, "/") {
		made := false
		if err := unix.Mkdirat(fd, c, 0o700); err == nil {
			made = true
		} else if !errors.Is(err, unix.EEXIST) {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("evidence: mkdir %s: %w", c, err)
		}
		next, err := unix.Openat(fd, c, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, fmt.Errorf("evidence: open %s: %w (a symlink is refused)", c, err)
		}
		if made {
			if err := unix.Fchown(next, e.uid, e.gid); err != nil {
				_ = unix.Close(next)
				return -1, err
			}
		}
		fd = next
	}
	return fd, nil
}
