package firewall

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// tokenRecord is the guard's record, in its state directory, of the pf
// enable reference it holds: written as soon as `pfctl -E` returns,
// removed once the reference is released. The firewall's own file, not
// one of netcfg's route records: they are the route table's, and this is
// no route.
const tokenRecord = "pf-guard.token"

const tokenHeader = "# thinkpol firewall: the pf enable reference (pfctl -E) the IPv6 guard holds; released with pfctl -X"

// pfToken is a pf enable reference: the token `pfctl -E` printed and
// the pid of that pfctl, which `pfctl -s References` lists with it.
type pfToken struct {
	value uint64
	pid   int
}

// bootSession names this boot of the machine. The state directory
// outlives a reboot and pf's references don't: a record of another boot
// holds nothing.
var bootSession = sync.OnceValues(func() (string, error) {
	s, err := unix.Sysctl("kern.bootsessionuuid")
	if err == nil && s == "" {
		err = errors.New("empty")
	}
	if err != nil {
		return "", fmt.Errorf("firewall: kern.bootsessionuuid: %w", err)
	}
	return s, nil
})

// tokenStore keeps the record in dir (made 0700 if missing, opened
// through trusteddir, every file reached relative to its descriptor).
type tokenStore struct {
	dir  string
	boot func() (string, error)
}

// recordState is what read found.
type recordState int

const (
	recordNone  recordState = iota // no record: no reference held
	recordHeld                     // a reference this boot's guard took
	recordStale                    // a record of another boot, or one that can't be read: it holds nothing that can be released
)

// read reads the record. A stale one should be removed.
func (s tokenStore) read() (pfToken, recordState, error) {
	boot, err := s.boot()
	if err != nil {
		return pfToken{}, recordNone, err
	}
	d, err := trusteddir.Make(s.dir)
	if err != nil {
		return pfToken{}, recordNone, err
	}
	defer func() { _ = d.Close() }()
	path := d.Name() + "/" + tokenRecord
	fd, err := unix.Openat(int(d.Fd()), tokenRecord, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	switch {
	case errors.Is(err, unix.ENOENT):
		return pfToken{}, recordNone, nil
	case errors.Is(err, unix.ELOOP):
		return pfToken{}, recordStale, nil // a symlink is never ours
	case err != nil:
		return pfToken{}, recordNone, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return pfToken{}, recordStale, nil
	}
	data, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return pfToken{}, recordNone, &os.PathError{Op: "read", Path: path, Err: err}
	}
	t, recBoot, ok := parseRecord(data)
	if !ok || recBoot != boot {
		return pfToken{}, recordStale, nil
	}
	return t, recordHeld, nil
}

// parseRecord reads "boot <session>" then "token <value> pid <pid>",
// comments and blank lines aside; anything else is no record.
func parseRecord(data []byte) (pfToken, string, bool) {
	var boot string
	var t pfToken
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' {
			continue
		}
		f := strings.Fields(l)
		switch n {
		case 0:
			if len(f) != 2 || f[0] != "boot" {
				return pfToken{}, "", false
			}
			boot = f[1]
		case 1:
			if len(f) != 4 || f[0] != "token" || f[2] != "pid" {
				return pfToken{}, "", false
			}
			v, err1 := strconv.ParseUint(f[1], 10, 64)
			pid, err2 := strconv.Atoi(f[3])
			if err1 != nil || err2 != nil || v == 0 || pid <= 0 {
				return pfToken{}, "", false
			}
			t = pfToken{value: v, pid: pid}
		default:
			return pfToken{}, "", false
		}
		n++
	}
	return t, boot, n == 2 && sc.Err() == nil
}

// write replaces the record with t, stamped with this boot, atomically.
func (s tokenStore) write(t pfToken) error {
	boot, err := s.boot()
	if err != nil {
		return err
	}
	d, err := trusteddir.Make(s.dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	dirfd := int(d.Fd())
	data := fmt.Sprintf("%s\nboot %s\ntoken %d pid %d\n", tokenHeader, boot, t.value, t.pid)
	tmp := tokenRecord + ".tmp"
	_ = unix.Unlinkat(dirfd, tmp, 0)
	fd, err := unix.Openat(dirfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return &os.PathError{Op: "create", Path: d.Name() + "/" + tmp, Err: err}
	}
	f := os.NewFile(uintptr(fd), tmp)
	err = errors.Join(func() error { _, err := f.Write([]byte(data)); return err }(), f.Sync())
	err = errors.Join(err, f.Close())
	if err == nil {
		err = unix.Renameat(dirfd, tmp, dirfd, tokenRecord)
	}
	if err != nil {
		_ = unix.Unlinkat(dirfd, tmp, 0)
		return fmt.Errorf("firewall: %s/%s: %w", d.Name(), tokenRecord, err)
	}
	return nil
}

// remove removes the record, if any.
func (s tokenStore) remove() error {
	d, err := trusteddir.Make(s.dir)
	if err != nil {
		return err
	}
	defer func() { _ = d.Close() }()
	if err := unix.Unlinkat(int(d.Fd()), tokenRecord, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return &os.PathError{Op: "remove", Path: d.Name() + "/" + tokenRecord, Err: err}
	}
	return nil
}
