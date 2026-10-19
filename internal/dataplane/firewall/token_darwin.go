package firewall

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"strconv"
	"strings"

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
// the pid of that pfctl, which `pfctl -s References` lists with it. A
// zero value is a token not known yet (recorded as "unknown").
type pfToken struct {
	value uint64
	pid   int
}

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
	data, err := trusteddir.ReadFile(d, tokenRecord)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return pfToken{}, recordNone, nil
	case errors.Is(err, unix.ELOOP), errors.Is(err, trusteddir.ErrNotRegular):
		return pfToken{}, recordStale, nil // a symlink or a fifo is never ours
	case err != nil:
		return pfToken{}, recordNone, err
	}
	t, recBoot, ok := parseRecord(data[:min(len(data), maxTokenRecord)])
	if !ok || recBoot != boot {
		return pfToken{}, recordStale, nil
	}
	return t, recordHeld, nil
}

// maxTokenRecord is as much of the record as is parsed: a record of ours
// is far shorter.
const maxTokenRecord = 4096

// parseRecord reads "boot <session>" then "token <value|unknown> pid
// <pid>", comments and blank lines aside; anything else is no record.
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
			var v uint64
			var err1 error
			if f[1] != "unknown" {
				if v, err1 = strconv.ParseUint(f[1], 10, 64); v == 0 {
					err1 = errors.New("zero")
				}
			}
			pid, err2 := strconv.Atoi(f[3])
			if err1 != nil || err2 != nil || pid <= 0 {
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
	value := "unknown"
	if t.value != 0 {
		value = strconv.FormatUint(t.value, 10)
	}
	data := fmt.Sprintf("%s\nboot %s\ntoken %s pid %d\n", tokenHeader, boot, value, t.pid)
	if err := trusteddir.WriteFile(d, tokenRecord, []byte(data)); err != nil {
		return fmt.Errorf("firewall: %w", err)
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
	return trusteddir.Remove(d, tokenRecord)
}
