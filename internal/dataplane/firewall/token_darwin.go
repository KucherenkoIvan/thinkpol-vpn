package firewall

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"os"
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
	d, err := trusteddir.Make(s.dir)
	if err != nil {
		return pfToken{}, recordNone, err
	}
	defer func() { _ = d.Close() }()
	return s.readIn(d)
}

// peek is read without making the record's directory: one that isn't
// there holds no record.
func (s tokenStore) peek() (pfToken, recordState, error) {
	d, err := trusteddir.Open(s.dir)
	if errors.Is(err, fs.ErrNotExist) {
		return pfToken{}, recordNone, nil
	}
	if err != nil {
		return pfToken{}, recordNone, err
	}
	defer func() { _ = d.Close() }()
	return s.readIn(d)
}

// readIn reads the record in d.
func (s tokenStore) readIn(d *os.File) (pfToken, recordState, error) {
	boot, err := s.boot()
	if err != nil {
		return pfToken{}, recordNone, err
	}
	body, err := trusteddir.ReadRecord(d, tokenRecord, boot)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return pfToken{}, recordNone, nil
	case errors.Is(err, unix.ELOOP), errors.Is(err, trusteddir.ErrNotRegular):
		return pfToken{}, recordStale, nil // a symlink or a fifo is never ours
	case errors.Is(err, trusteddir.ErrOtherBoot), errors.Is(err, trusteddir.ErrNoBoot):
		return pfToken{}, recordStale, nil
	case err != nil:
		return pfToken{}, recordNone, err
	}
	t, ok := parseTokenRecord(body)
	if !ok {
		return pfToken{}, recordStale, nil
	}
	return t, recordHeld, nil
}

// parseTokenRecord reads a record's body: "token <value|unknown> pid <pid>",
// comments and blank lines aside; anything else is no record.
func parseTokenRecord(body []byte) (pfToken, bool) {
	var t pfToken
	n := 0
	sc := bufio.NewScanner(bytes.NewReader(body))
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' {
			continue
		}
		f := strings.Fields(l)
		if n > 0 || len(f) != 4 || f[0] != "token" || f[2] != "pid" {
			return pfToken{}, false
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
			return pfToken{}, false
		}
		t = pfToken{value: v, pid: pid}
		n++
	}
	return t, n == 1 && sc.Err() == nil
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
	body := fmt.Sprintf("token %s pid %d\n", value, t.pid)
	if err := trusteddir.WriteRecord(d, tokenRecord, tokenHeader, boot, []byte(body)); err != nil {
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
