package netcfg

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"slices"
	"strconv"
	"strings"

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

// recordHeader starts a record. After it, trusteddir's boot line and the
// identities of the routes an owner added, one per line: the destination,
// and for a scoped route "scope <interface index>" (an index names the
// same interface for the whole boot).
const recordHeader = "# thinkpol netcfg: routes this owner added (RTF_PROTO2); rewritten on every change"

// readRecord reads the record name in dir; a missing one, or one written
// in another boot session than boot, is empty: LockDir outlives a reboot
// and the routes don't. A record without a boot line (empty, or comments
// only), with a line that isn't an identity, or that isn't a regular file
// is corrupt (isCorrupt), not empty: writeRecord didn't write it. Any
// other failure to read it is an error of its own.
func readRecord(dir *os.File, name string, boot string) (map[rkey]bool, error) {
	out := make(map[rkey]bool)
	body, err := trusteddir.ReadRecord(dir, name, boot)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, trusteddir.ErrOtherBoot):
		return out, nil
	case errors.Is(err, trusteddir.ErrNoBoot), errors.Is(err, trusteddir.ErrNotRegular), errors.Is(err, unix.ELOOP):
		return nil, corruptRecordError{err}
	case err != nil:
		return nil, err
	}
	path := dir.Name() + "/" + name
	sc := bufio.NewScanner(bytes.NewReader(body))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" || line[0] == '#' {
			continue
		}
		k, err := parseRecordLine(line)
		if err != nil {
			// By its number in the body: errors reach diagnostics.
			return nil, corruptRecordError{fmt.Errorf("%s: bad line %d after the boot line: %v", path, n, err)}
		}
		out[k] = true
	}
	if err := sc.Err(); err != nil {
		return nil, corruptRecordError{fmt.Errorf("%s: %w", path, err)}
	}
	return out, nil
}

// corruptRecordError is readRecord's error for a record writeRecord
// didn't write.
type corruptRecordError struct{ err error }

func (e corruptRecordError) Error() string { return e.err.Error() }
func (e corruptRecordError) Unwrap() error { return e.err }

// isCorrupt reports readRecord's error for a corrupt record: one that
// says nothing of which routes are its owner's.
func isCorrupt(err error) bool {
	var c corruptRecordError
	return errors.As(err, &c)
}

// setAsideName is where owner's corrupt record is moved in boot: kept for
// a person to look at, and, while it is there, what Survey reports for
// the rest of the boot (the routes the record named may still be there,
// and are no owner's any more).
func setAsideName(owner Owner, boot string) string { return recordName(owner) + ".corrupt-" + boot }

// setAside moves owner's record in dir to setAsideName, replacing one set
// aside earlier in boot. Only while no configurator of owner can write the
// record: under owner's lock.
func setAside(dir *os.File, owner Owner, boot string) error {
	return trusteddir.Rename(dir, recordName(owner), setAsideName(owner, boot))
}

// setAsideRecords are the paths of the records set aside in boot in dir.
func setAsideRecords(dir *os.File, boot string) ([]string, error) {
	var out []string
	for _, o := range Owners {
		name := setAsideName(o, boot)
		var st unix.Stat_t
		err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
		switch {
		case err == nil:
			out = append(out, dir.Name()+"/"+name)
		case !errors.Is(err, unix.ENOENT):
			return nil, &os.PathError{Op: "stat", Path: dir.Name() + "/" + name, Err: err}
		}
	}
	return out, nil
}

// writeRecord replaces the record name in dir atomically, stamped with
// boot; an empty one is removed.
func writeRecord(dir *os.File, name string, boot string, owned map[rkey]bool) error {
	if len(owned) == 0 {
		return trusteddir.Remove(dir, name)
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
	for _, k := range ks {
		b.WriteString(k.String() + "\n")
	}
	return trusteddir.WriteRecord(dir, name, recordHeader, boot, b.Bytes())
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
