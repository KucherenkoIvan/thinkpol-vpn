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

// lifetime says whether a change outlives a reboot.
type lifetime string

const (
	volatile   lifetime = "volatile"   // kernel state: a reboot removes it
	persistent lifetime = "persistent" // on disk: it outlives a reboot
)

// state is where a journaled change is.
type state string

const (
	stateIntent     state = "intent"  // its undo is on disk; it may have been applied in part
	stateApplied    state = "applied" // applied
	stateUndone     state = "undone"
	stateUndoFailed state = "undo-failed"
	// stateGoneWithBoot: a volatile change of an earlier boot, which that
	// reboot removed; the snapshot diff checks it is gone.
	stateGoneWithBoot state = "gone-with-reboot"
)

// pending says the change may still be on the host.
func (s state) pending() bool {
	return s == stateIntent || s == stateApplied || s == stateUndoFailed
}

// journalName is the journal's file in a run's directory.
const journalName = "journal.jsonl"

const journalMagic = "thinkpol-devicetest"

// line is one line of the journal: the header, a change's state, or the
// closing line.
type line struct {
	Journal string          `json:"journal,omitempty"`
	Version int             `json:"version,omitempty"`
	Run     string          `json:"run,omitempty"`
	Closed  bool            `json:"closed,omitempty"`
	Seq     int             `json:"seq,omitempty"`
	State   state           `json:"state,omitempty"`
	Kind    string          `json:"kind,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Does    string          `json:"does,omitempty"`
	Undo    string          `json:"undo,omitempty"`
	Life    lifetime        `json:"lifetime,omitempty"`
	Boot    string          `json:"boot"`
	Wall    time.Time       `json:"wall"`
	MonoNS  int64           `json:"mono_ns"`
	Err     string          `json:"err,omitempty"`
}

// entry is one change as the journal holds it: its intent's description,
// its latest state and parameters.
type entry struct {
	Seq      int
	Kind     string
	Params   json.RawMessage
	Does     string
	Undo     string
	Lifetime lifetime
	// Boot is the boot session it was applied in.
	Boot  string
	State state
	Err   string
}

// journal is a run's append-only record of its changes: each change's
// undo is on disk, synced, before the change is made. One line per state
// change, each synced. Only the last line can be cut short by a crash (it
// has no newline): reading the journal back cuts it off before anything
// is appended. A complete line that doesn't parse is corruption.
type journal struct {
	mu   sync.Mutex
	f    *os.File
	run  string
	boot string
	seq  int
	all  map[int]*entry
	done bool
	// torn says a cut-short last line was found and cut off.
	torn bool
}

// createJournal starts a run's journal in dir, which must not have one;
// the header and the directory are synced before it returns.
func createJournal(dir *os.File, run, boot string) (*journal, error) {
	fd, err := unix.Openat(int(dir.Fd()), journalName, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, &os.PathError{Op: "create", Path: filepath.Join(dir.Name(), journalName), Err: err}
	}
	j := &journal{f: os.NewFile(uintptr(fd), filepath.Join(dir.Name(), journalName)), run: run, boot: boot, all: map[int]*entry{}}
	if err := j.append(&line{Journal: journalMagic, Version: 1, Run: run}); err != nil {
		_ = j.f.Close()
		return nil, err
	}
	if err := fullSync(dir); err != nil {
		_ = j.f.Close()
		return nil, fmt.Errorf("journal: sync %s: %w", dir.Name(), err)
	}
	return j, nil
}

// openJournal reads the journal in dir back, cuts off a torn last line,
// and opens it for more lines, boot being the session now.
func openJournal(dir *os.File, boot string) (*journal, error) {
	path := filepath.Join(dir.Name(), journalName)
	data, err := trusteddir.ReadFile(dir, journalName)
	if err != nil {
		return nil, err
	}
	j, complete, err := parseJournal(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	fd, err := unix.Openat(int(dir.Fd()), journalName, unix.O_WRONLY|unix.O_APPEND|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	j.f, j.boot = os.NewFile(uintptr(fd), path), boot
	if j.torn {
		if err := errors.Join(j.f.Truncate(int64(complete)), fullSync(j.f)); err != nil {
			_ = j.f.Close()
			return nil, fmt.Errorf("%s: cutting off the torn line: %w", path, err)
		}
	}
	return j, nil
}

// parseJournal reads data's complete lines; complete is their length. A
// tail without a newline is torn; any complete line must parse.
func parseJournal(data []byte) (*journal, int, error) {
	j := &journal{all: map[int]*entry{}}
	complete := bytes.LastIndexByte(data, '\n') + 1
	j.torn = complete < len(data)
	for i, raw := range bytes.Split(data[:complete], []byte("\n")) {
		if len(raw) == 0 {
			continue
		}
		var l line
		if err := json.Unmarshal(raw, &l); err != nil {
			return nil, 0, fmt.Errorf("line %d: %w", i+1, err)
		}
		if i == 0 {
			if l.Journal != journalMagic || l.Version != 1 || l.Run == "" {
				return nil, 0, errors.New("not a devicetest journal")
			}
			j.run = l.Run
			continue
		}
		j.fold(l)
	}
	if j.run == "" {
		return nil, 0, errors.New("no header")
	}
	return j, complete, nil
}

func (j *journal) fold(l line) {
	if l.Closed {
		j.done = true
		return
	}
	e := j.all[l.Seq]
	if e == nil {
		e = &entry{Seq: l.Seq}
		j.all[l.Seq] = e
	}
	if l.State == stateIntent {
		e.Kind, e.Does, e.Undo, e.Lifetime, e.Boot = l.Kind, l.Does, l.Undo, l.Life, l.Boot
	}
	if l.Params != nil {
		e.Params = l.Params
	}
	e.State, e.Err = l.State, l.Err
	j.seq = max(j.seq, l.Seq)
}

// closed says the journal was closed: its run restored clean.
func (j *journal) closed() bool { return j.done }

// intent writes a's intent, its undo included, and syncs it: only then may
// a be applied.
func (j *journal) intent(a action, params json.RawMessage) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.done {
		return 0, errors.New("journal: closed")
	}
	seq := j.seq + 1
	l := line{Seq: seq, State: stateIntent, Kind: a.kind(), Params: params, Does: a.does(), Undo: a.undoText(), Life: a.lifetime()}
	if err := j.append(&l); err != nil {
		return 0, err
	}
	j.seq = seq
	j.fold(l)
	return seq, nil
}

// mark records seq's new state (and parameters learnt on the way, nil for
// none).
func (j *journal) mark(seq int, s state, params json.RawMessage, cause error) error {
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

// entries are the journal's changes in the order they were made.
func (j *journal) entries() []entry {
	j.mu.Lock()
	defer j.mu.Unlock()
	out := make([]entry, 0, len(j.all))
	for _, e := range j.all {
		out = append(out, *e)
	}
	slices.SortFunc(out, func(a, b entry) int { return a.Seq - b.Seq })
	return out
}

// pending are the changes that may still be on the host, newest first:
// the order they are undone in.
func (j *journal) pending() []entry {
	var out []entry
	for _, e := range slices.Backward(j.entries()) {
		if e.State.pending() {
			out = append(out, e)
		}
	}
	return out
}

// close writes the closing line: nothing is left to undo.
func (j *journal) close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.done {
		return j.f.Close()
	}
	err := j.append(&line{Closed: true})
	j.done = err == nil
	return errors.Join(err, j.f.Close())
}

// release closes the file without closing the journal: a later restore
// replays it.
func (j *journal) release() error { return j.f.Close() }

func (j *journal) append(l *line) error {
	l.Boot, l.Wall, l.MonoNS = j.boot, time.Now().UTC(), monotonicNS()
	b, err := json.Marshal(l)
	if err != nil {
		return err
	}
	if _, err := j.f.Write(append(b, '\n')); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	if err := fullSync(j.f); err != nil {
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
