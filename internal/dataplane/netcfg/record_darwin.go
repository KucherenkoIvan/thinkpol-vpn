package netcfg

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"syscall"

	"golang.org/x/sys/unix"
)

// ownerLock is an owner's exclusive flock in LockDir, held for its
// configurator's life (released by the kernel when the process dies).
type ownerLock struct{ fd int }

// lockOwner takes owner's lock in dir, made first if need be. dir and
// its parent must be this user's and writable by no one else, since the
// record next to the lock decides which routes are deleted.
func lockOwner(dir string, owner Owner) (*ownerLock, error) {
	if err := makePrivateDir(dir); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, owner.String()+".lock")
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = unix.Close(fd)
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, err
	}
	return &ownerLock{fd: fd}, nil
}

func (l *ownerLock) release() error { return unix.Close(l.fd) }

// makePrivateDir makes dir and its parent (0700) if missing, and checks
// both are real directories of this user that no one else can write to.
func makePrivateDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for _, d := range []string{filepath.Dir(dir), dir} {
		fi, err := os.Lstat(d)
		if err != nil {
			return err
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !fi.IsDir() || !ok || int(st.Uid) != os.Geteuid() || fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s: want a directory of uid %d that no one else can write to", d, os.Geteuid())
		}
	}
	return nil
}

func recordPath(dir string, owner Owner) string {
	return filepath.Join(dir, owner.String()+".routes")
}

// recordHeader starts a record: the destinations of the routes an owner
// added, one per line.
const recordHeader = "# thinkpol netcfg: routes this owner added (RTF_PROTO2); rewritten on every change"

// readRecord reads an owner's record; a missing one is empty.
func readRecord(path string) (map[netip.Prefix]bool, error) {
	out := make(map[netip.Prefix]bool)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		p, err := netip.ParsePrefix(line)
		if err != nil || p != p.Masked() {
			return nil, fmt.Errorf("%s: bad line %q", path, line)
		}
		out[p] = true
	}
	return out, sc.Err()
}

// writeRecord replaces the record atomically; an empty one is removed.
func writeRecord(path string, owned map[netip.Prefix]bool) error {
	if len(owned) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	ps := make([]netip.Prefix, 0, len(owned))
	for p := range owned {
		ps = append(ps, p)
	}
	slices.SortFunc(ps, comparePrefixes)
	var b bytes.Buffer
	b.WriteString(recordHeader + "\n")
	for _, p := range ps {
		b.WriteString(p.String() + "\n")
	}
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b.Bytes()); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
