package supervisor

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// procSys is where the root namespace's sysctls are (the supervisor's own
// /proc: it runs in the root namespace).
var procSys = "/proc/sys"

// forwardingFile records, in Options.RuntimeDir, the forwarding sysctls the
// supervisor changed, so a successor (after a crash) restores them.
const forwardingFile = "forwarding.json"

// rootForwarding turns on the root namespace's forwarding for the families
// the spaces' egress and dials need, and only when it is off: a node that
// forwards already (a container runtime, its own routing) is left alone,
// and its forwarding isn't the supervisor's to confine. What it turned on
// (owned) it confines to the spaces (applyIsolation), turns off again when
// no space needs it any more and on Close, and records in a runtime file, so
// a successor adopts it after a crash.
//
// Turning forwarding on changes other sysctls as a side effect (IPv4 resets
// accept_redirects and every interface's forwarding, IPv6 every interface's
// forwarding), and turning it off resets them again: each family's record
// keeps their earlier values to put back. IPv6 forwarding makes Linux ignore
// router advertisements on interfaces with accept_ra 1, which would cost an
// RA-configured VPS its IPv6 default route; those get accept_ra 2 first. A
// value is put back only if it still holds what the supervisor left there.
type rootForwarding struct {
	mu   sync.Mutex
	file string
	fams [2]*forwardingChange // IPv4, IPv6; nil when not the supervisor's
}

type forwardingChange struct {
	// Main is the family's forwarding switch.
	Main sysctlChange `json:"main"`
	// Side are what writing Main resets (to be set back after Main is);
	// Before what the supervisor changed before it (accept_ra).
	Side   []sysctlChange `json:"side,omitempty"`
	Before []sysctlChange `json:"before,omitempty"`
}

type sysctlChange struct {
	Key      string `json:"key"`
	Original string `json:"original"`
	Written  string `json:"written"`
}

var forwardingKeys = [2]string{"net/ipv4/ip_forward", "net/ipv6/conf/all/forwarding"}

// sideKeys are the sysctls writing a family's forwarding switch resets.
func sideKeys(fam int) ([]string, error) {
	pattern := []string{"net/ipv4/conf/*/accept_redirects", "net/ipv4/conf/*/forwarding"}
	if fam == 1 {
		pattern = []string{"net/ipv6/conf/*/forwarding"}
	}
	var keys []string
	for _, p := range pattern {
		matches, err := filepath.Glob(filepath.Join(procSys, p))
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			key, _ := filepath.Rel(procSys, m)
			if key != forwardingKeys[fam] {
				keys = append(keys, key)
			}
		}
	}
	return keys, nil
}

// load adopts the record a predecessor left: the families whose switch
// still holds what it wrote.
func (f *rootForwarding) load(dir string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.file = filepath.Join(dir, forwardingFile)
	b, err := os.ReadFile(f.file)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var rec [2]*forwardingChange
	if err := json.Unmarshal(b, &rec); err != nil {
		return fmt.Errorf("%s: %w", f.file, err)
	}
	for i, c := range rec {
		if c != nil && c.Main.Key == forwardingKeys[i] {
			if v, err := readSysctl(c.Main.Key); err == nil && v == c.Main.Written {
				f.fams[i] = c
			}
		}
	}
	return f.save()
}

// save writes the record, or removes it when nothing is the supervisor's.
func (f *rootForwarding) save() error {
	if f.file == "" {
		return nil
	}
	if f.fams == [2]*forwardingChange{} {
		if err := os.Remove(f.file); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return nil
	}
	b, err := json.Marshal(f.fams)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(f.file), 0o700); err != nil {
		return err
	}
	tmp := f.file + ".new"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.file)
}

// owned are the families whose forwarding the supervisor turned on.
func (f *rootForwarding) owned() [2]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return [2]bool{f.fams[0] != nil, f.fams[1] != nil}
}

// willOwn are the families the supervisor will own once want is ensured:
// those it owns, and those it is about to turn on. The tables confine them
// before the switch is flipped.
func (f *rootForwarding) willOwn(want [2]bool) [2]bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out [2]bool
	for i := range out {
		out[i] = f.fams[i] != nil
		if want[i] && !out[i] {
			v, err := readSysctl(forwardingKeys[i])
			out[i] = err == nil && v != "1"
		}
	}
	return out
}

// ensure turns forwarding on for the families in want that are off, and
// off for those the supervisor turned on that want no longer has.
func (f *rootForwarding) ensure(want [2]bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	var errs []error
	for i := range want {
		switch {
		case want[i] && f.fams[i] == nil:
			if err := f.enable(i); err != nil {
				errs = append(errs, err)
			}
		case !want[i] && f.fams[i] != nil:
			errs = append(errs, f.restoreFamily(i))
		}
	}
	errs = append(errs, f.save())
	return errors.Join(errs...)
}

func (f *rootForwarding) enable(fam int) error {
	main := forwardingKeys[fam]
	was, err := readSysctl(main)
	if err != nil || was == "1" {
		return err
	}
	c := &forwardingChange{Main: sysctlChange{Key: main, Original: was, Written: "1"}}
	if fam == 1 {
		dirs, err := os.ReadDir(filepath.Join(procSys, "net/ipv6/conf"))
		if err != nil {
			return err
		}
		for _, d := range dirs {
			if d.Name() == "all" || strings.HasPrefix(d.Name(), LinkPrefix) {
				continue
			}
			key := "net/ipv6/conf/" + d.Name() + "/accept_ra"
			if v, err := readSysctl(key); err == nil && v == "1" {
				if err := writeSysctl(key, "2"); err != nil {
					return err
				}
				c.Before = append(c.Before, sysctlChange{Key: key, Original: "1", Written: "2"})
			}
		}
	}
	keys, err := sideKeys(fam)
	if err != nil {
		return err
	}
	before := map[string]string{}
	for _, k := range keys {
		if v, err := readSysctl(k); err == nil {
			before[k] = v
		}
	}
	if err := writeSysctl(main, "1"); err != nil {
		f.fams[fam] = c // accept_ra may have changed: put it back with the rest
		_ = f.restoreFamily(fam)
		return err
	}
	for _, k := range keys {
		// Every one, changed or not: writing the switch back resets them
		// all again.
		if v, err := readSysctl(k); err == nil && before[k] != "" {
			c.Side = append(c.Side, sysctlChange{Key: k, Original: before[k], Written: v})
		}
	}
	f.fams[fam] = c
	return nil
}

// restoreFamily puts back what enable changed: the switch, then what writing
// it reset (which the switch's own write resets again), then accept_ra;
// each only if it still holds what the supervisor left there. A switch that
// can't be turned off stays the supervisor's, with all it changed: still to
// be confined (applyIsolation) and recorded for the next try or successor;
// and IPv6's accept_ra stays 2 while its forwarding is on.
func (f *rootForwarding) restoreFamily(fam int) error {
	c := f.fams[fam]
	if c == nil {
		return nil
	}
	held := func(s sysctlChange) bool {
		v, err := readSysctl(s.Key)
		return err == nil && v == s.Written
	}
	side := slices.DeleteFunc(slices.Clone(c.Side), func(s sysctlChange) bool { return !held(s) })
	var errs []error
	if held(c.Main) {
		if err := writeSysctl(c.Main.Key, c.Main.Original); err != nil {
			return err
		}
		for _, s := range side {
			errs = append(errs, writeSysctl(s.Key, s.Original))
		}
	}
	for _, s := range c.Before {
		if held(s) {
			errs = append(errs, writeSysctl(s.Key, s.Original))
		}
	}
	f.fams[fam] = nil
	return errors.Join(errs...)
}

// restore puts back everything the supervisor changed (Close).
func (f *rootForwarding) restore() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	errs := []error{f.restoreFamily(1), f.restoreFamily(0)}
	errs = append(errs, f.save())
	return errors.Join(errs...)
}

func readSysctl(key string) (string, error) {
	b, err := os.ReadFile(filepath.Join(procSys, key))
	if err != nil {
		return "", fmt.Errorf("sysctl %s: %w", key, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// writeSysctl writes a sysctl (writeSysctlFile; tests stand in for the
// kernel's side effects).
var writeSysctl = writeSysctlFile

// writeSysctlFile writes a sysctl; one whose interface went away meanwhile
// is nothing to write.
func writeSysctlFile(key, value string) error {
	err := os.WriteFile(filepath.Join(procSys, key), []byte(value), 0)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("sysctl %s: %w", key, err)
	}
	return nil
}

// maxFlows is the per-space flow cap: MaxFlowsPerSpace, or a quarter of
// the node's conntrack table.
func maxFlows(opt int) int {
	switch {
	case opt < 0:
		return 0
	case opt > 0:
		return opt
	}
	v, err := readSysctl("net/netfilter/nf_conntrack_max")
	n, perr := strconv.Atoi(v)
	if err != nil || perr != nil || n < 4 {
		return 65536
	}
	return n / 4
}
