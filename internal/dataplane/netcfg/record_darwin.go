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
	"time"

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
// only), with a line that isn't an identity, that isn't a regular file,
// or that is a symlink is corrupt (isCorrupt), not empty: writeRecord
// didn't write it. Any other failure to read it is an error of its own.
func readRecord(dir *os.File, name string, boot string) (map[rkey]bool, error) {
	out := make(map[rkey]bool)
	body, err := trusteddir.ReadRecord(dir, name, boot)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, trusteddir.ErrOtherBoot):
		return out, nil
	case errors.Is(err, trusteddir.ErrNoBoot), errors.Is(err, trusteddir.ErrNotRegular), errors.Is(err, unix.ELOOP):
		return nil, corruptRecordError{err, false}
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
			return nil, corruptRecordError{fmt.Errorf("%s: bad line %d after the boot line: %v", path, n, err), true}
		}
		out[k] = true
	}
	if err := sc.Err(); err != nil {
		return nil, corruptRecordError{fmt.Errorf("%s: %w", path, err), true}
	}
	return out, nil
}

// corruptRecordError is readRecord's error for a record writeRecord
// didn't write. thisBoot says its boot line named this boot: it was
// corrupted in this boot, whatever its mtime says.
type corruptRecordError struct {
	err      error
	thisBoot bool
}

func (e corruptRecordError) Error() string { return e.err.Error() }
func (e corruptRecordError) Unwrap() error { return e.err }

// isCorrupt reports readRecord's error for a corrupt record: one that
// says nothing of which routes are its owner's.
func isCorrupt(err error) bool {
	var c corruptRecordError
	return errors.As(err, &c)
}

// ofThisBoot reports readRecord's error for a corrupt record whose boot
// line named this boot.
func ofThisBoot(err error) bool {
	var c corruptRecordError
	return errors.As(err, &c) && c.thisBoot
}

// setAsideName is where owner's corrupt record is moved in boot: kept for
// a person to look at for the rest of the boot (removed at the owner's
// first start in a later one, clearSetAside), and what Survey reports
// while it is there.
func setAsideName(owner Owner, boot string) string { return recordName(owner) + ".corrupt-" + boot }

// setAside moves owner's record in dir to setAsideName, replacing one set
// aside earlier in boot. renameat(2) replaces a file with a file and a
// directory with an empty directory only, so an earlier one of the other
// kind is removed first; a non-empty directory there stays, and the
// record with it (its owner fails to start until someone removes it).
// Only while no configurator of owner can write the record: under
// owner's lock.
func setAside(dir *os.File, owner Owner, boot string) error {
	from, to := recordName(owner), setAsideName(owner, boot)
	err := trusteddir.Rename(dir, from, to)
	if errors.Is(err, unix.ENOTDIR) || errors.Is(err, unix.EISDIR) || errors.Is(err, unix.ENOTEMPTY) || errors.Is(err, unix.EEXIST) {
		if trusteddir.RemoveEntry(dir, to) == nil {
			err = trusteddir.Rename(dir, from, to)
		}
	}
	return err
}

// clearSetAside removes owner's records set aside in boots other than
// boot: the routes they named went with those boots. Under owner's lock,
// at its start. What it can't list or remove stays (a non-empty
// directory, say): that costs only the space, so it never fails a start.
func clearSetAside(dir *os.File, owner Owner, boot string) {
	names, _ := trusteddir.Names(dir) // the names read before a failure still go
	prefix, keep := recordName(owner)+".corrupt-", setAsideName(owner, boot)
	for _, n := range names {
		if strings.HasPrefix(n, prefix) && n != keep {
			_ = trusteddir.RemoveEntry(dir, n)
		}
	}
}

// corruptRecord is the corrupt record name in dir as Survey reports it:
// its path, when it was last written, and why it is corrupt (why, or else
// what reading it again says; a set-aside one someone has since made
// valid still says it was set aside). ok is false for one that is gone,
// or that was last written before booted unless its boot line names this
// boot: whatever it named went with that boot. Only content that proves
// nothing of its boot (no boot line, not a regular file, a symlink) is
// judged by its mtime: a restore that keeps times, or a clock step, never
// hides one that names this boot. A failed stat reports it: reporting
// errs on the side of telling and never fails a survey.
func corruptRecord(dir *os.File, name, boot string, booted time.Time, why error) (_ CorruptRecord, ok bool) {
	var st unix.Stat_t
	err := unix.Fstatat(int(dir.Fd()), name, &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return CorruptRecord{}, false
	}
	if why == nil {
		_, why = readRecord(dir, name, boot)
	}
	r := CorruptRecord{Path: dir.Name() + "/" + name}
	if err == nil {
		r.Modified = time.Unix(st.Mtim.Unix())
		if r.Modified.Before(booted) && !ofThisBoot(why) {
			return CorruptRecord{}, false
		}
	}
	r.Reason = "set aside; reads clean now"
	if why != nil {
		r.Reason = strings.TrimPrefix(why.Error(), r.Path+": ")
	}
	return r, true
}

// bootTime is when this boot began (kern.boottime); the zero time if it
// can't be read, so that every corrupt record is reported.
func bootTime() time.Time {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil {
		return time.Time{}
	}
	return time.Unix(tv.Unix())
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
