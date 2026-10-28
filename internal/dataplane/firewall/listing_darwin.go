package firewall

import (
	"errors"
	"io/fs"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// The guard's own readings of pf and of its record, for what reads them
// from outside the agent: the device-test harness (lab/devicetest)
// compares pf with its baseline through these, so a listing means one
// thing wherever it is read.

// ParsePfEnabled reads `pfctl -s info`: whether its Status line says
// Enabled; an error without one.
func ParsePfEnabled(info []byte) (bool, error) { return parseEnabled(info) }

// SkippedNames reads `pfctl -s Interfaces -v` as every name pf skips, lo0
// included; an error when a line too long to read cuts the listing.
func SkippedNames(ifaces []byte) ([]string, error) { return skippedNames(ifaces) }

// GuardReferenceHeld says the guard's record in dir names a pf reference
// taken in this boot: a missing directory or record, a record of another
// boot, a symlink, a non-regular file or a record that doesn't parse
// holds nothing. It only reads: the directory is never made.
func GuardReferenceHeld(dir string) (bool, error) {
	boot, err := trusteddir.BootSession()
	if err != nil {
		return false, err
	}
	d, err := trusteddir.Open(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = d.Close() }()
	body, err := trusteddir.ReadRecord(d, tokenRecord, boot)
	switch {
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, unix.ELOOP), errors.Is(err, trusteddir.ErrNotRegular),
		errors.Is(err, trusteddir.ErrOtherBoot), errors.Is(err, trusteddir.ErrNoBoot):
		return false, nil
	case err != nil:
		return false, err
	}
	_, ok := parseTokenRecord(body)
	return ok, nil
}
