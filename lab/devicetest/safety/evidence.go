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

// Evidence is a run's evidence folder as root writes into it on its
// owner's behalf: opened once, checked as the owner's
// (trusteddir.OpenOwnedBy), every file made relative to it, never through
// a symlink nor over an existing file, and handed to the owner. Root never
// removes anything in it: captures are kept.
type Evidence struct {
	dir      *os.File
	uid, gid int
}

// OpenEvidence opens the folder at path, which must be uid's.
func OpenEvidence(path string, uid, gid int) (*Evidence, error) {
	d, err := trusteddir.OpenOwnedBy(path, uid)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(d.Fd()), &st); err != nil {
		_ = d.Close()
		return nil, err
	}
	if int(st.Uid) != uid {
		_ = d.Close()
		return nil, fmt.Errorf("%s: owned by uid %d, not the run's user (%d)", path, st.Uid, uid)
	}
	return &Evidence{dir: d, uid: uid, gid: gid}, nil
}

// Path is the folder's path.
func (e *Evidence) Path() string { return e.dir.Name() }

// Close closes the folder.
func (e *Evidence) Close() error { return e.dir.Close() }

var relPath = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*(/[A-Za-z0-9][A-Za-z0-9._-]*)*$`)

// Create makes the file rel (a relative path, its directories made as
// needed), which must not exist yet, owned by the folder's owner.
func (e *Evidence) Create(rel string) (*os.File, error) {
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
		return nil, &os.PathError{Op: "create", Path: filepath.Join(e.Path(), rel), Err: err}
	}
	if err := unix.Fchown(fd, e.uid, e.gid); err != nil {
		_ = unix.Close(fd)
		return nil, &os.PathError{Op: "chown", Path: filepath.Join(e.Path(), rel), Err: err}
	}
	return os.NewFile(uintptr(fd), filepath.Join(e.Path(), rel)), nil
}

// WriteFile creates rel with data.
func (e *Evidence) WriteFile(rel string, data []byte) error {
	f, err := e.Create(rel)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	return errors.Join(err, f.Close())
}

// mkdirs opens dir under the folder, making what is missing (0700, the
// owner's), one component at a time, never through a symlink.
func (e *Evidence) mkdirs(dir string) (int, error) {
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
