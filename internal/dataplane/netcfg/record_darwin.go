package netcfg

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// ownerLock is an owner's exclusive flock in LockDir, held for its
// configurator's life (released by the kernel when the process dies).
type ownerLock struct{ f *os.File }

// lockOwner takes owner's lock in dir.
func lockOwner(dir *os.File, owner Owner) (*ownerLock, error) {
	f, err := trusteddir.Lock(dir, owner.String()+".lock")
	if errors.Is(err, trusteddir.ErrLocked) {
		return nil, ErrBusy
	}
	if err != nil {
		return nil, err
	}
	return &ownerLock{f: f}, nil
}

func (l *ownerLock) release() error { return l.f.Close() }

func recordName(owner Owner) string { return owner.String() + ".routes" }

// recordHeader starts a record: the boot session it was written in, then
// the identities of the routes an owner added, one per line: the
// destination, and for a scoped route "scope <interface index>" (an
// index names the same interface for the whole boot).
const recordHeader = "# thinkpol netcfg: routes this owner added (RTF_PROTO2); rewritten on every change"

// bootSession names this boot of the machine. LockDir outlives a reboot
// and the routes don't: a record of another boot session holds nothing.
var bootSession = sync.OnceValues(func() (string, error) {
	s, err := unix.Sysctl("kern.bootsessionuuid")
	if err == nil && s == "" {
		err = errors.New("empty")
	}
	if err != nil {
		return "", fmt.Errorf("kern.bootsessionuuid: %w", err)
	}
	return s, nil
})

// readRecord reads the record name in dir; a missing one, or one written
// in another boot session than boot, is empty.
func readRecord(dir *os.File, name string, boot string) (map[rkey]bool, error) {
	out := make(map[rkey]bool)
	path := dir.Name() + "/" + name
	fd, err := unix.Openat(int(dir.Fd()), name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENOENT) {
		return out, nil
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	booted := false
	for sc.Scan() {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		if !booted {
			s, ok := strings.CutPrefix(line, "boot ")
			if !ok {
				return nil, fmt.Errorf("%s: no boot session", path)
			}
			if s != boot {
				return out, nil // the routes went with that boot
			}
			booted = true
			continue
		}
		k, err := parseRecordLine(line)
		if err != nil {
			return nil, fmt.Errorf("%s: bad line %q", path, line)
		}
		out[k] = true
	}
	return out, sc.Err()
}

// writeRecord replaces the record name in dir atomically, stamped with
// boot; an empty one is removed.
func writeRecord(dir *os.File, name string, boot string, owned map[rkey]bool) error {
	dirfd := int(dir.Fd())
	if len(owned) == 0 {
		if err := unix.Unlinkat(dirfd, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
			return &os.PathError{Op: "remove", Path: dir.Name() + "/" + name, Err: err}
		}
		return nil
	}
	ks := make([]rkey, 0, len(owned))
	for k := range owned {
		ks = append(ks, k)
	}
	slices.SortFunc(ks, func(a, b rkey) int {
		if c := comparePrefixes(a.dst, b.dst); c != 0 {
			return c
		}
		return a.scope - b.scope
	})
	var b bytes.Buffer
	b.WriteString(recordHeader + "\nboot " + boot + "\n")
	for _, k := range ks {
		b.WriteString(k.String() + "\n")
	}
	tmp := name + ".tmp"
	_ = unix.Unlinkat(dirfd, tmp, 0)
	fd, err := unix.Openat(dirfd, tmp, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return &os.PathError{Op: "create", Path: dir.Name() + "/" + tmp, Err: err}
	}
	f := os.NewFile(uintptr(fd), tmp)
	err = errors.Join(func() error { _, err := f.Write(b.Bytes()); return err }(), f.Sync())
	err = errors.Join(err, f.Close())
	if err == nil {
		err = unix.Renameat(dirfd, tmp, dirfd, name)
	}
	if err != nil {
		_ = unix.Unlinkat(dirfd, tmp, 0)
		return fmt.Errorf("%s: %w", dir.Name()+"/"+name, err)
	}
	return nil
}

// parseRecordLine reads a record's line: "<prefix>" or "<prefix> scope <index>".
func parseRecordLine(line string) (rkey, error) {
	dst, scope, scoped := strings.Cut(line, " scope ")
	p, err := netip.ParsePrefix(dst)
	if err != nil || p != p.Masked() {
		return rkey{}, errors.New("not a masked prefix")
	}
	k := unscoped(p)
	if scoped {
		if k.scope, err = strconv.Atoi(scope); err != nil || k.scope <= 0 {
			return rkey{}, errors.New("bad scope")
		}
	}
	return k, nil
}
