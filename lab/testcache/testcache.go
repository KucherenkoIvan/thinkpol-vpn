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
// tallies of the run that passed. Only passes are recorded.
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
const recordVersion = "testcache-v1"

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
// covers or which start fresh in every node.
type Resolver func(nodePath string) string

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
	Version string
	Key     string
	Tally   Tally
}

// Lookup returns the tally of a recorded pass of action whose inputs, read
// through resolve, hash as they do now. ok is false on a miss: no record, a
// record that doesn't decode or names another key, or an input that changed.
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
	// Recently used records survive Trim.
	now := time.Now()
	_ = os.Chtimes(s.path(id, "a"), now, now)
	_ = os.Chtimes(s.path(key, "p"), now, now)
	return p.Tally, true
}

// ErrInputChanged is Record's error when an input changed after the run
// started: what the run read may not be what is there now.
var ErrInputChanged = errors.New("testcache: an input changed during the run")

// Record stores a pass of action, started at started, that read the inputs
// in testLog (its -test.testlogfile, run in the node directory action.Dir).
func (s Store) Record(action Action, testLog []byte, resolve Resolver, started time.Time, t Tally) error {
	inputs, err := ParseTestLog(testLog, action.Dir)
	if err != nil {
		return err
	}
	id := action.ID()
	key, err := passKey(id, inputs, resolve, started)
	if err != nil {
		return err
	}
	if err := s.write(id, "a", actionRecord{Version: recordVersion, Key: id, Inputs: inputs}); err != nil {
		return err
	}
	return s.write(key, "p", passRecord{Version: recordVersion, Key: key, Tally: t})
}

// passKey hashes the action with every input's content. A non-zero
// changedAfter fails it when an input file was modified at or after then.
func passKey(actionID string, inputs []string, resolve Resolver, changedAfter time.Time) (string, error) {
	parts := []string{recordVersion, "pass", actionID}
	for _, in := range inputs {
		h, err := hashInput(resolve(in), changedAfter)
		if err != nil {
			return "", err
		}
		parts = append(parts, in, h)
	}
	return sum(parts...), nil
}

// hashInput hashes what a test sees at hostPath: a regular file's content, a
// directory's entries' names and types, or that it is missing. Stat follows
// symlinks, as the test's open and stat did.
func hashInput(hostPath string, changedAfter time.Time) (string, error) {
	if hostPath == "" {
		return "ignored", nil
	}
	info, err := os.Stat(hostPath)
	if errors.Is(err, fs.ErrNotExist) {
		return "missing", nil
	}
	if err != nil {
		return "", err
	}
	switch {
	case info.IsDir():
		entries, err := os.ReadDir(hostPath)
		if err != nil {
			return "", err
		}
		h := sha256.New()
		for _, e := range entries {
			fmt.Fprintf(h, "%s\x00%v\x00", e.Name(), e.Type())
		}
		return "dir:" + hex.EncodeToString(h.Sum(nil)), nil
	case info.Mode().IsRegular():
		// A directory's time changes with any entry, a run's own lab/bin
		// included; its listing is hashed anyway.
		if !changedAfter.IsZero() && !info.ModTime().Before(changedAfter) {
			return "", fmt.Errorf("%w: %s", ErrInputChanged, hostPath)
		}
		h, err := HashFile(hostPath)
		if err != nil {
			return "", err
		}
		return "file:" + h, nil
	default:
		return "mode:" + info.Mode().Type().String(), nil
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

// MountResolver resolves the node paths under each mount point (a node
// path) to the host directory mounted there; everything else is ignored.
func MountResolver(mounts map[string]string) Resolver {
	return func(p string) string {
		for at, host := range mounts {
			if rel, ok := strings.CutPrefix(p, at); ok && (rel == "" || rel[0] == '/') {
				return filepath.Join(host, filepath.FromSlash(rel))
			}
		}
		return ""
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
		fmt.Fprintf(h, "%d:%s\n", len(p), p)
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
