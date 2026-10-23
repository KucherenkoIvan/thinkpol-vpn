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
// only) is corrupt, not empty: it was not written by writeRecord.
func readRecord(dir *os.File, name string, boot string) (map[rkey]bool, error) {
	out := make(map[rkey]bool)
	body, err := trusteddir.ReadRecord(dir, name, boot)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, trusteddir.ErrOtherBoot):
		return out, nil
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
			return nil, fmt.Errorf("%s: bad line %d after the boot line: %v", path, n, err)
		}
		out[k] = true
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
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
