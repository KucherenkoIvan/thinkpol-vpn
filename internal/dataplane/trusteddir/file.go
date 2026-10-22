//go:build unix

package trusteddir

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ErrNotRegular: the file is not a regular one (a fifo, a directory).
var ErrNotRegular = errors.New("not a regular file")

// openRegular opens the file name in dir with flags (perm if it creates
// it), close-on-exec, never through a symlink (ELOOP) nor blocking on a
// fifo, and only if it is a regular file (ErrNotRegular otherwise).
func openRegular(dir *os.File, name string, flags int, perm uint32) (*os.File, error) {
	path := filepath.Join(dir.Name(), name)
	fd, err := unix.Openat(int(dir.Fd()), name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, perm)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = f.Close()
		return nil, &os.PathError{Op: "stat", Path: path, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = f.Close()
		return nil, fmt.Errorf("%s: %w", path, ErrNotRegular)
	}
	return f, nil
}

// ReadFile reads the regular file name in dir. It never follows a
// symlink (ELOOP) nor blocks on a fifo (ErrNotRegular); a missing file is
// fs.ErrNotExist.
func ReadFile(dir *os.File, name string) ([]byte, error) {
	f, err := openRegular(dir, name, unix.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, &os.PathError{Op: "read", Path: f.Name(), Err: err}
	}
	return data, nil
}

// WriteFile replaces the file name in dir with data (0600): a new file
// next to it, name+".tmp" (reserved for this), synced, then renamed over
// it. Neither it nor the new file is ever reached through a symlink.
// Callers serialise their writes to one name. The replacement is atomic
// for readers and across a crash of the process, not durable across a
// power loss (the directory isn't synced): what a reboot may lose is a
// boot-scoped record, which the next boot ignores anyway.
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

// ErrOtherBoot: the record was written in another boot session than the
// one it was read in.
var ErrOtherBoot = errors.New("written in another boot session")

// ErrNoBoot: the record has no boot line before its body, so WriteRecord
// didn't write it.
var ErrNoBoot = errors.New("no boot session")

// WriteRecord replaces the record name in dir (as WriteFile does) with
// header, one comment line ('#'), then "boot <boot>", then body. boot is
// one field, so ReadRecord reads back the session written.
func WriteRecord(dir *os.File, name, header, boot string, body []byte) error {
	path := filepath.Join(dir.Name(), name)
	if !strings.HasPrefix(header, "#") || strings.Contains(header, "\n") {
		return fmt.Errorf("%s: header %q is not one comment line", path, header)
	}
	if f := strings.Fields(boot); len(f) != 1 || f[0] != boot {
		return fmt.Errorf("%s: boot session %q is not one field", path, boot)
	}
	data := append([]byte(header+"\nboot "+boot+"\n"), body...)
	return WriteFile(dir, name, data)
}

// ReadRecord reads the record name in dir (as ReadFile does) and returns
// its body: what follows its boot line, which must come before anything
// but blank and comment ('#') lines and name a session (ErrNoBoot
// otherwise), and name boot (ErrOtherBoot otherwise). Its errors never
// quote the record's content: a record may hold what must not leave it
// (the pf guard's token), and its errors reach logs and diagnostics.
func ReadRecord(dir *os.File, name, boot string) ([]byte, error) {
	data, err := ReadFile(dir, name)
	if err != nil {
		return nil, err
	}
	path := filepath.Join(dir.Name(), name)
	n := 0
	for rest := data; len(rest) > 0; {
		line, next, _ := bytes.Cut(rest, []byte("\n"))
		rest = next
		n++
		l := strings.TrimSpace(string(line))
		if l == "" || l[0] == '#' {
			continue
		}
		f := strings.Fields(l)
		if f[0] != "boot" {
			return nil, fmt.Errorf("%s: line %d, before the boot session, is no boot line: %w", path, n, ErrNoBoot)
		}
		if len(f) == 1 {
			return nil, fmt.Errorf("%s: a boot line without a session: %w", path, ErrNoBoot)
		}
		if strings.Join(f[1:], " ") != boot {
			return nil, fmt.Errorf("%s: %w", path, ErrOtherBoot)
		}
		return rest, nil
	}
	return nil, fmt.Errorf("%s: %w", path, ErrNoBoot)
}
