// Package testcache remembers which runs of a package's tests in a lab node
// passed, so labctl gotest can skip a run whose every input is unchanged,
// the way go test's own cache does on the host.
//
// A run's key has two parts, as go test's has. The action is what was run
// and where: the test binary's hash, the lab image, the Docker engine and
// its kernel, the harness that set the node up, the working directory, and
// the args and environment given to the binary. The inputs are the files
// the test binary itself opened or stat'ed (its -test.testlogfile), each
// hashed by content as it is now. The action record lists the inputs' names;
// the pass record, keyed by the action and the inputs' hashes, holds the
// tallies of the run that passed and when it was recorded. Only passes are
// recorded, and a pass serves for MaxPassAge from then, however often it is
// used.
//
// A pass is not recorded when a watched input (one of the checkout's: a
// file, a directory, or for a missing one the nearest directory above it
// that exists), or a directory above it up to the checkout's root, was
// modified or had its inode changed (mtime or ctime) since the run started:
// what the run read may not be what is hashed now. The ctime is what an old
// file copied or moved over an input (cp -p, mv, rsync -t) can't carry
// back; the directories above are what a directory renamed or a directory
// symlink re-pointed over the input's path changes. A file added or renamed
// in one of them during the run keeps it from being recorded too.
//
// What a test reads without going through package os in the test process
// (a subprocess, a raw syscall, an exec of an absolute path it never
// stat'ed) is not an input: go test's cache has the same blind spot.
//
// Records are plain files, shared by every run of the user on the machine:
// each is written to a temporary file and renamed into place, so a reader
// sees a whole record or none, and one that doesn't decode, or names another
// key, is a miss.
package testcache

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

// NoCacheEnv, set to anything but empty, makes labctl gotest run every
// package and record nothing.
const NoCacheEnv = "LAB_NOCACHE"

// recordVersion changes whenever what a key covers does: older records then
// never match.
const recordVersion = "testcache-v2"

// MaxPassAge is how long a recorded pass serves: a test that depends on the
// date (a certificate in testdata that expires) runs again at least this
// often.
const MaxPassAge = 7 * 24 * time.Hour

// clockSlack widens "since the run started": file times come from a
// coarser clock than time.Now (the kernel's tick, or a file system that
// keeps seconds), so a change just after the start can carry a time just
// before it.
const clockSlack = 2 * time.Second

// Action is what a package's tests were run as. Every field is part of the
// key.
type Action struct {
	ImportPath string
	TestBinary string   // sha256 of the test binary, hex
	Image      string   // the lab image's ID
	Engine     string   // the Docker engine's version and kernel
	Harness    string   // sha256 of what set the lab up (labctl), hex
	Dir        string   // the working directory in the node
	Args       []string // given to the test binary, in order
	Env        []string // NAME=value given to the test binary, in order
}

// ID is the action's key.
func (a Action) ID() string {
	b, err := json.Marshal(a)
	if err != nil {
		panic(err) // strings only
	}
	return sum(recordVersion, "action", string(b))
}

// Tally is what a recorded run's tests did.
type Tally struct {
	Passed, Skipped int
}

// Resolver maps a path in the node to the file on the host it reads, or ""
// when it is none of the checkout's or the lab's binaries': the image's own
// files and the node's scratch space (/tmp, /proc, ...), which the action
// covers or which start fresh in every node. A non-empty watchRoot is the
// host directory of the watched mount it is under: a change since the run
// started to it, or to a directory above it up to watchRoot, keeps the run
// from being recorded.
type Resolver func(nodePath string) (hostPath, watchRoot string)

// Store is a directory of records.
type Store struct {
	Dir string
}

// DefaultDir is the user's cache directory's thinkpol-lab/gotest.
func DefaultDir() (string, error) {
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "thinkpol-lab", "gotest"), nil
}

type actionRecord struct {
	Version string
	Key     string
	Inputs  []string // node paths, sorted
}

type passRecord struct {
	Version  string
	Key      string
	Tally    Tally
	Recorded time.Time
}

// Lookup returns the tally of a recorded pass of action whose inputs, read
// through resolve, hash as they do now. ok is false on a miss: no record, a
// record that doesn't decode or names another key, an input that changed,
// or a pass recorded more than MaxPassAge ago (or in the future).
func (s Store) Lookup(action Action, resolve Resolver) (t Tally, ok bool) {
	id := action.ID()
	var a actionRecord
	if !s.read(id, "a", &a) {
		return Tally{}, false
	}
	key, err := passKey(id, a.Inputs, resolve, time.Time{})
	if err != nil {
		return Tally{}, false
	}
	var p passRecord
	if !s.read(key, "p", &p) {
		return Tally{}, false
	}
	now := time.Now()
	if age := now.Sub(p.Recorded); age < -clockSlack || age > MaxPassAge {
		return Tally{}, false
	}
	// Recently used records survive Trim.
	_ = os.Chtimes(s.path(id, "a"), now, now)
	_ = os.Chtimes(s.path(key, "p"), now, now)
	return p.Tally, true
}

// ErrInputChanged is Record's error when a watched input changed after the
// run started: what the run read may not be what is there now.
var ErrInputChanged = errors.New("testcache: an input changed during the run")

// Record stores a pass of action, started at started, that read the inputs
// in testLog (its -test.testlogfile, run in the node directory action.Dir).
func (s Store) Record(action Action, testLog []byte, resolve Resolver, started time.Time, t Tally) error {
	read, err := ParseTestLog(testLog, action.Dir)
	if err != nil {
		return err
	}
	// Only the inputs that resolve: the rest (a t.TempDir's random name)
	// would make every run's list another, and the action record keeps one.
	var inputs []string
	for _, in := range read {
		if host, _ := resolve(in); host != "" {
			inputs = append(inputs, in)
		}
	}
	id := action.ID()
	key, err := passKey(id, inputs, resolve, started)
	if err != nil {
		return err
	}
	if err := s.write(id, "a", actionRecord{Version: recordVersion, Key: id, Inputs: inputs}); err != nil {
		return err
	}
	return s.write(key, "p", passRecord{Version: recordVersion, Key: key, Tally: t, Recorded: time.Now()})
}

// passKey hashes the action with every input's content. A non-zero since
// fails it when a watched input, or a directory above it up to its mount,
// changed at or after then.
func passKey(actionID string, inputs []string, resolve Resolver, since time.Time) (string, error) {
	parts := []string{recordVersion, "pass", actionID}
	checkedDirs := map[string]bool{}
	for _, in := range inputs {
		host, root := resolve(in)
		if host == "" {
			return "", fmt.Errorf("testcache: %s is under no mount", in)
		}
		var changedSince time.Time
		if root != "" {
			changedSince = since
		}
		h, err := hashInput(host, changedSince)
		if err != nil {
			return "", err
		}
		if !changedSince.IsZero() {
			if err := checkDirsUnchanged(host, root, changedSince, checkedDirs); err != nil {
				return "", err
			}
		}
		parts = append(parts, in, h)
	}
	return sum(parts...), nil
}

// checkDirsUnchanged fails when a directory above hostPath, up to root,
// changed at or after since: one renamed or re-pointed over the input's path
// leaves the input's own times old. checked holds the directories already
// found unchanged, with every directory above them.
func checkDirsUnchanged(hostPath, root string, since time.Time, checked map[string]bool) error {
	root = filepath.Clean(root)
	for dir := filepath.Dir(hostPath); !checked[dir]; dir = filepath.Dir(dir) {
		if dir != root && !strings.HasPrefix(dir, root+string(filepath.Separator)) {
			return nil
		}
		info, err := os.Stat(dir)
		switch {
		case errors.Is(err, fs.ErrNotExist): // above a missing input, or gone: its parent changed
		case err != nil:
			return err
		default:
			if err := checkUnchanged(dir, info, since); err != nil {
				return err
			}
		}
		checked[dir] = true
		if dir == root {
			return nil
		}
	}
	return nil
}

// CheckUnchanged fails with ErrInputChanged when hostPath (symlinks
// followed, and a symlink there itself) was modified or had its inode
// changed at or after since, as a watched input is checked.
func CheckUnchanged(hostPath string, since time.Time) error {
	info, err := os.Stat(hostPath)
	if errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("%w: %s", ErrInputChanged, hostPath)
	}
	if err != nil {
		return err
	}
	return checkUnchanged(hostPath, info, since)
}

// hashInput hashes what a test sees at hostPath: a regular file's content, a
// directory's entries' names and types, or that it is missing. Stat follows
// symlinks, as the test's open and stat did. A non-zero since fails it when
// the input, or for a missing one the nearest directory above it that
// exists, changed at or after then.
func hashInput(hostPath string, since time.Time) (string, error) {
	info, err := os.Stat(hostPath)
	if errors.Is(err, fs.ErrNotExist) {
		if !since.IsZero() {
			if err := checkMissingUnchanged(hostPath, since); err != nil {
				return "", err
			}
		}
		return "missing", nil
	}
	if err != nil {
		return "", err
	}
	if !since.IsZero() {
		if err := checkUnchanged(hostPath, info, since); err != nil {
			return "", err
		}
	}
	switch {
	case info.IsDir():
		entries, err := os.ReadDir(hostPath)
		if err != nil {
			return "", err
		}
		h := sha256.New()
		for _, e := range entries {
			_, _ = fmt.Fprintf(h, "%s\x00%v\x00", e.Name(), e.Type())
		}
		return "dir:" + hex.EncodeToString(h.Sum(nil)), nil
	case info.Mode().IsRegular():
		h, err := HashFile(hostPath)
		if err != nil {
			return "", err
		}
		return "file:" + h, nil
	default:
		return "mode:" + info.Mode().Type().String(), nil
	}
}

// checkUnchanged fails when info (hostPath's, symlinks followed), or a
// symlink at hostPath itself, was modified or had its inode changed at or
// after since, less the clock slack.
func checkUnchanged(hostPath string, info fs.FileInfo, since time.Time) error {
	cutoff := since.Add(-clockSlack)
	changed := func(fi fs.FileInfo) bool {
		ctime, ok := changeTime(fi)
		return !fi.ModTime().Before(cutoff) || ok && !ctime.Before(cutoff)
	}
	if changed(info) {
		return fmt.Errorf("%w: %s", ErrInputChanged, hostPath)
	}
	if link, err := os.Lstat(hostPath); err == nil && link.Mode()&fs.ModeSymlink != 0 && changed(link) {
		return fmt.Errorf("%w: %s", ErrInputChanged, hostPath)
	}
	return nil
}

// checkMissingUnchanged fails when the nearest directory above the missing
// hostPath that exists changed at or after since: the input may have been
// there when the run looked.
func checkMissingUnchanged(hostPath string, since time.Time) error {
	for dir := filepath.Dir(hostPath); ; dir = filepath.Dir(dir) {
		info, err := os.Stat(dir)
		if err == nil {
			return checkUnchanged(dir, info, since)
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if dir == filepath.Dir(dir) {
			return err
		}
	}
}

// ParseTestLog returns, sorted and once each, the absolute node paths a test
// binary's -test.testlogfile says it opened, stat'ed or changed into, the
// relative ones resolved from dir and later chdirs. A log without its
// header is an error: the binary never wrote it, or not to the end.
func ParseTestLog(log []byte, dir string) ([]string, error) {
	sc := bufio.NewScanner(bytes.NewReader(log))
	sc.Buffer(nil, 1<<20)
	if !sc.Scan() || sc.Text() != "# test log" {
		return nil, errors.New("testcache: not a test log")
	}
	seen := map[string]bool{}
	cwd := dir
	for sc.Scan() {
		op, name, ok := strings.Cut(sc.Text(), " ")
		if !ok {
			continue
		}
		switch op {
		case "open", "stat", "chdir":
		default: // getenv: the node's environment is the action's
			continue
		}
		if !path.IsAbs(name) {
			name = path.Join(cwd, name)
		}
		name = path.Clean(name)
		if op == "chdir" {
			cwd = name
		}
		seen[name] = true
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("testcache: test log: %w", err)
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	slices.Sort(out)
	return out, nil
}

// Mount is a host directory mounted in the node.
type Mount struct {
	Node, Host string
	// Watch: the run doesn't write here, so a change since it started is
	// someone else's (the checkout, not the run's own binary directory).
	Watch bool
}

// MountResolver resolves the node paths under each mount's node path to the
// host directory mounted there, the watch root being that directory on a
// watched mount; everything else is ignored.
func MountResolver(mounts ...Mount) Resolver {
	return func(p string) (string, string) {
		for _, m := range mounts {
			if rel, ok := strings.CutPrefix(p, m.Node); ok && (rel == "" || rel[0] == '/') {
				var root string
				if m.Watch {
					root = filepath.Clean(m.Host)
				}
				return filepath.Join(m.Host, filepath.FromSlash(rel)), root
			}
		}
		return "", ""
	}
}

func (s Store) path(key, kind string) string {
	return filepath.Join(s.Dir, key[:2], key+"-"+kind)
}

// read decodes the record into v; false when it is missing, corrupt, of
// another version, or for another key.
func (s Store) read(key, kind string, v any) bool {
	b, err := os.ReadFile(s.path(key, kind))
	if err != nil {
		return false
	}
	if err := json.Unmarshal(b, v); err != nil {
		return false
	}
	var head struct{ Version, Key string }
	if err := json.Unmarshal(b, &head); err != nil {
		return false
	}
	return head.Version == recordVersion && head.Key == key
}

func (s Store) write(key, kind string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	p := s.path(key, kind)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return fmt.Errorf("testcache: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".tmp-*")
	if err != nil {
		return fmt.Errorf("testcache: %w", err)
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, err = tmp.Write(b)
	if err = errors.Join(err, tmp.Close()); err != nil {
		return fmt.Errorf("testcache: %w", err)
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return fmt.Errorf("testcache: %w", err)
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		return fmt.Errorf("testcache: %w", err)
	}
	return nil
}

// trimMarker's modification time is when the store was last trimmed.
const trimMarker = "trimmed"

// Trim removes the records not written or used for maxAge, and temporary
// files that old: at most once per interval, whoever runs it first.
func (s Store) Trim(maxAge, interval time.Duration) error {
	marker := filepath.Join(s.Dir, trimMarker)
	now := time.Now()
	if info, err := os.Stat(marker); err == nil && now.Sub(info.ModTime()) < interval {
		return nil
	}
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(marker, nil, 0o644); err != nil {
		return err
	}
	if err := os.Chtimes(marker, now, now); err != nil {
		return err
	}
	return filepath.WalkDir(s.Dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil // another run's trim was first
			}
			return err
		}
		if d.IsDir() || p == marker {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if now.Sub(info.ModTime()) > maxAge {
			if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
		return nil
	})
}

func sum(parts ...string) string {
	h := sha256.New()
	for _, p := range parts {
		_, _ = fmt.Fprintf(h, "%d:%s\n", len(p), p)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// HashFile is the sha256 of a file's content, hex.
func HashFile(name string) (string, error) {
	f, err := os.Open(name)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
