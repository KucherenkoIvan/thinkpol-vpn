//go:build darwin || linux

package safety

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// Lifetime says whether a change outlives a reboot.
type Lifetime string

const (
	// Volatile changes live in the kernel: a reboot removes them.
	Volatile Lifetime = "volatile"
	// Persistent changes are on disk: they outlive a reboot.
	Persistent Lifetime = "persistent"
)

// State is where a journaled action is.
type State string

const (
	StateIntent     State = "intent"  // its undo is on disk; it may have been applied in part
	StateApplied    State = "applied" // applied
	StateUndone     State = "undone"
	StateUndoFailed State = "undo-failed"
	// StateGoneWithBoot: a volatile change of an earlier boot, which that
	// reboot removed; the snapshot diff checks it is gone.
	StateGoneWithBoot State = "gone-with-reboot"
)

// pending says the action may still be on the host.
func (s State) pending() bool {
	return s == StateIntent || s == StateApplied || s == StateUndoFailed
}

// JournalName is the journal's file in a run's directory.
const JournalName = "journal.jsonl"

const journalMagic = "thinkpol-devicetest"

// line is one line of the journal: the header, an action's state, or the
// closing line.
type line struct {
	Journal string          `json:"journal,omitempty"`
	Version int             `json:"version,omitempty"`
	Run     string          `json:"run,omitempty"`
	Closed  bool            `json:"closed,omitempty"`
	Seq     int             `json:"seq,omitempty"`
	State   State           `json:"state,omitempty"`
	Kind    string          `json:"kind,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Does    string          `json:"does,omitempty"`
	Undo    string          `json:"undo,omitempty"`
	Life    Lifetime        `json:"lifetime,omitempty"`
	Boot    string          `json:"boot"`
	Wall    time.Time       `json:"wall"`
	MonoNS  int64           `json:"mono_ns"`
	Err     string          `json:"err,omitempty"`
}

// Entry is one action as the journal holds it: its intent's description
// and its latest state and parameters.
type Entry struct {
	Seq      int
	Kind     string
	Params   json.RawMessage
	Does     string
	Undo     string
	Lifetime Lifetime
	// Boot is the boot session it was applied in.
	Boot  string
	State State
	Err   string
}

// Journal is a run's append-only record of its changes: each action's
// undo is on disk, synced, before the action runs. One line per state
// change, each synced; a line cut by a crash is ignored when it is read
// back (only the last line can be).
type Journal struct {
	mu      sync.Mutex
	f       *os.File
	run     string
	boot    string
	seq     int
	entries map[int]*Entry
	closed  bool
	// Torn says the last line was cut short (a crash while it was written).
	Torn bool
}

// CreateJournal starts a run's journal in dir, which must not have one.
func CreateJournal(dir *os.File, run, boot string) (*Journal, error) {
	fd, err := unix.Openat(int(dir.Fd()), JournalName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: filepath.Join(dir.Name(), JournalName), Err: err}
	}
	j := &Journal{f: os.NewFile(uintptr(fd), filepath.Join(dir.Name(), JournalName)), run: run, boot: boot, entries: map[int]*Entry{}}
	if err := j.append(&line{Journal: journalMagic, Version: 1, Run: run}); err != nil {
		_ = j.f.Close()
		return nil, err
	}
	if err := unix.Fsync(int(dir.Fd())); err != nil {
		_ = j.f.Close()
		return nil, fmt.Errorf("journal: sync %s: %w", dir.Name(), err)
	}
	return j, nil
}

// OpenJournal reads the journal in dir back and opens it for more lines,
// boot being the session now.
func OpenJournal(dir *os.File, boot string) (*Journal, error) {
	data, err := trusteddir.ReadFile(dir, JournalName)
	if err != nil {
		return nil, err
	}
	j, err := parseJournal(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir.Name(), JournalName), err)
	}
	fd, err := unix.Openat(int(dir.Fd()), JournalName, unix.O_WRONLY|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: filepath.Join(dir.Name(), JournalName), Err: err}
	}
	j.f, j.boot = os.NewFile(uintptr(fd), filepath.Join(dir.Name(), JournalName)), boot
	return j, nil
}

func parseJournal(data []byte) (*Journal, error) {
	j := &Journal{entries: map[int]*Entry{}}
	lines := bytes.Split(data, []byte("\n"))
	for i, raw := range lines {
		if len(bytes.TrimSpace(raw)) == 0 {
			continue
		}
		var l line
		if err := json.Unmarshal(raw, &l); err != nil {
			if i >= len(lines)-2 { // the last line, cut by a crash
				j.Torn = true
				continue
			}
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if i == 0 {
			if l.Journal != journalMagic || l.Version != 1 {
				return nil, errors.New("not a devicetest journal")
			}
			j.run = l.Run
			continue
		}
		j.fold(l)
	}
	if j.run == "" {
		return nil, errors.New("no header")
	}
	return j, nil
}

func (j *Journal) fold(l line) {
	if l.Closed {
		j.closed = true
		return
	}
	e := j.entries[l.Seq]
	if e == nil {
		e = &Entry{Seq: l.Seq}
		j.entries[l.Seq] = e
	}
	if l.State == StateIntent {
		e.Kind, e.Does, e.Undo, e.Lifetime, e.Boot = l.Kind, l.Does, l.Undo, l.Life, l.Boot
	}
	if l.Params != nil {
		e.Params = l.Params
	}
	e.State, e.Err = l.State, l.Err
	j.seq = max(j.seq, l.Seq)
}

// Run is the run the journal belongs to.
func (j *Journal) Run() string { return j.run }

// Closed says the journal was closed: its run restored.
func (j *Journal) Closed() bool { return j.closed }

// Intent writes a's intent, its undo included, and syncs it: only then may
// a be applied.
func (j *Journal) Intent(a Action, params json.RawMessage) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return 0, errors.New("journal: closed")
	}
	seq := j.seq + 1
	l := line{Seq: seq, State: StateIntent, Kind: a.Kind(), Params: params, Does: a.Does(), Undo: a.UndoText(), Life: a.Lifetime()}
	if err := j.append(&l); err != nil {
		return 0, err
	}
	j.seq = seq
	j.fold(l)
	return seq, nil
}

// Mark records seq's new state (and parameters learnt on the way, nil for
// none).
func (j *Journal) Mark(seq int, s State, params json.RawMessage, cause error) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	l := line{Seq: seq, State: s, Params: params}
	if cause != nil {
		l.Err = cause.Error()
	}
	if err := j.append(&l); err != nil {
		return err
	}
	j.fold(l)
	return nil
}

// Entries are the journal's actions in the order they were taken.
func (j *Journal) Entries() []Entry {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]Entry, 0, len(j.entries))
	for _, e := range j.entries {
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b Entry) int { return a.Seq - b.Seq })
	return out
}

// Pending are the actions that may still be on the host, last first: the
// order they are undone in.
func (j *Journal) Pending() []Entry {
	var out []Entry
	for _, e := range slices.Backward(j.Entries()) {
		if e.State.pending() {
			out = append(out, e)
		}
	}
	return out
}

// Close writes the closing line: nothing is left to undo.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	err := j.append(&line{Closed: true})
	j.closed = err == nil
	return errors.Join(err, j.f.Close())
}

// release closes the file without closing the journal: a later reader
// replays it.
func (j *Journal) release() error { return j.f.Close() }

func (j *Journal) append(l *line) error {
	l.Boot, l.Wall, l.MonoNS = j.boot, time.Now().UTC(), monotonicNS()
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if _, err := j.f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	if err := j.f.Sync(); err != nil {
		return fmt.Errorf("journal: sync: %w", err)
	}
	return nil
}

// monotonicNS is the system's monotonic clock, for ordering lines across
// processes; 0 if it can't be read.
func monotonicNS() int64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return ts.Nano()
}
