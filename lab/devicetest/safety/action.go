//go:build darwin || linux

package safety

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Action is one typed change to the host, with its own undo. The set of
// kinds is closed (Decode): a plan names one, it can't add one.
type Action interface {
	Kind() string
	Lifetime() Lifetime
	// Does and UndoText describe the change and its undo, for the plan's
	// listing and the journal.
	Does() string
	UndoText() string
	// Pre refuses the action when its undo couldn't put the host back.
	Pre(ctx context.Context, h *Host) error
	// Apply makes the change. It returns what it learnt that the undo
	// needs (a pid), as the action's new parameters, or nil.
	Apply(ctx context.Context, h *Host) (json.RawMessage, error)
	// Undo removes the change; it checks first whether the change is
	// there, so it is safe to repeat.
	Undo(ctx context.Context, h *Host) error
}

// Spec is an action as a plan names it and the journal keeps it.
type Spec struct {
	Kind   string          `json:"kind"`
	Params json.RawMessage `json:"params"`
}

// Decode is the action spec names. Only the kinds here exist.
func Decode(spec Spec) (Action, error) {
	switch spec.Kind {
	case KindFile:
		return decodeStrict[*FileAction](spec.Params)
	case KindCapture:
		return decodeStrict[*CaptureAction](spec.Params)
	case KindPfMain:
		return decodePfMain(spec.Params)
	}
	return nil, fmt.Errorf("no action of kind %q", spec.Kind)
}

func decodeStrict[T interface {
	Action
	validate() error
}](params json.RawMessage) (Action, error) {
	var a T
	d := json.NewDecoder(bytes.NewReader(params))
	d.DisallowUnknownFields()
	if err := d.Decode(&a); err != nil {
		return nil, fmt.Errorf("action parameters: %w", err)
	}
	if any(a) == nil {
		return nil, errors.New("action parameters: none")
	}
	if err := a.validate(); err != nil {
		return nil, err
	}
	return a, nil
}

// Host is what actions, snapshots and the restore work with.
type Host struct {
	// RunDir is the run's root-owned directory: journal, baseline,
	// heartbeat, the dead-man's files.
	RunDir *os.File
	// Evidence is where raw output goes; nil when there is nowhere.
	Evidence *Evidence
	Boot     string
	// Baseline is the snapshot taken before any change; nil before it.
	Baseline *Snapshot
	// Surfaces are what a snapshot reads; nil: the OS's (the core's
	// tests give their own, so they never read the real host's pf).
	Surfaces []Surface
	captures *captures
	beats    int
	logf     func(format string, a ...any)
}

func (h *Host) log(format string, a ...any) {
	if h.logf != nil {
		h.logf(format, a...)
	}
}

// commandTimeout bounds every command the core runs.
const commandTimeout = 30 * time.Second

// output is what one command printed.
type output struct {
	Stdout, Stderr []byte
	Code           int
	Err            string
}

// run runs argv (an absolute path first) with stdin (nil: none), in the C
// locale, bounded by commandTimeout.
func run(ctx context.Context, argv []string, stdin []byte) output {
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = time.Second
	err := cmd.Run()
	out := output{Stdout: stdout.Bytes(), Stderr: stderr.Bytes(), Code: cmd.ProcessState.ExitCode()}
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		out.Err = fmt.Sprintf("%s: no answer within %v", strings.Join(argv, " "), commandTimeout)
	case err != nil:
		out.Err = fmt.Sprintf("%s: %v", strings.Join(argv, " "), err)
	}
	return out
}

// Engine applies actions through the journal: nothing changes on the host
// without a restore plan for it.
type Engine struct {
	h *Host
	j *Journal
	// armed says the dead-man is watching.
	armed func() error
}

// NewEngine is an engine over h and j; armed says whether a dead-man
// watches the run.
func NewEngine(h *Host, j *Journal, armed func() error) *Engine {
	return &Engine{h: h, j: j, armed: armed}
}

// ErrNoRestorePlan: an action was refused before anything changed, because
// what would put the host back isn't in place.
var ErrNoRestorePlan = errors.New("refused: no restore plan")

// Do applies spec: refused unless the baseline is taken, the dead-man is
// armed and the action's undo is synced to the journal first. An apply
// that fails is undone at once.
func (e *Engine) Do(ctx context.Context, spec Spec) (int, error) {
	if e.h.Baseline == nil {
		return 0, fmt.Errorf("%w: no baseline of the host yet", ErrNoRestorePlan)
	}
	if err := e.armed(); err != nil {
		return 0, fmt.Errorf("%w: the dead-man: %w", ErrNoRestorePlan, err)
	}
	a, err := Decode(spec)
	if err != nil {
		return 0, err
	}
	if err := a.Pre(ctx, e.h); err != nil {
		return 0, fmt.Errorf("%s: refused: %w", a.Does(), err)
	}
	seq, err := e.j.Intent(a, spec.Params)
	if err != nil {
		return 0, fmt.Errorf("%w: the journal: %w", ErrNoRestorePlan, err)
	}
	learnt, err := a.Apply(ctx, e.h)
	if err != nil {
		e.h.log("%s failed: %v; undoing it", a.Does(), err)
		return seq, errors.Join(err, e.undo(ctx, e.entry(seq)))
	}
	return seq, e.j.Mark(seq, StateApplied, learnt, nil)
}

// UndoLast undoes the newest action still on the host.
func (e *Engine) UndoLast(ctx context.Context) error {
	p := e.j.Pending()
	if len(p) == 0 {
		return errors.New("nothing to undo")
	}
	return e.undo(ctx, p[0])
}

func (e *Engine) entry(seq int) Entry {
	for _, en := range e.j.Entries() {
		if en.Seq == seq {
			return en
		}
	}
	return Entry{Seq: seq}
}

// undo undoes one journaled action. A volatile one of an earlier boot is
// gone with that boot and isn't touched.
func (e *Engine) undo(ctx context.Context, en Entry) error {
	if en.Lifetime == Volatile && en.Boot != e.h.Boot {
		return e.j.Mark(en.Seq, StateGoneWithBoot, nil, nil)
	}
	a, err := Decode(Spec{Kind: en.Kind, Params: en.Params})
	if err == nil {
		err = a.Undo(ctx, e.h)
	}
	e.h.beat()
	if err != nil {
		return errors.Join(fmt.Errorf("undo %d (%s): %w", en.Seq, en.Does, err), e.j.Mark(en.Seq, StateUndoFailed, nil, err))
	}
	return e.j.Mark(en.Seq, StateUndone, nil, nil)
}
