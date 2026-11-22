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
	"syscall"
	"time"
)

// host is what changes, snapshots and the restore work with.
type host struct {
	// runDir is the run's root-owned directory: journal, snapshots,
	// heartbeat, the dead-man's files.
	runDir *os.File
	// evidence is where raw output goes; nil when there is nowhere.
	evidence *evidence
	boot     string
	// baseline is the snapshot taken before any change; nil before it, or
	// when it can't be read back (baselineErr says why).
	baseline    *snapshot
	baselineErr error
	// surfaces are what a snapshot reads; nil: the OS's (the core's tests
	// give their own, so they never read the real host's pf).
	surfaces []surface
	captures *captures
	beats    int
	logf     func(format string, a ...any)
	// exec runs every command the core runs on the host; nil: run. The
	// core's tests give a fake, so no test runs pfctl.
	exec runner
	// runBoot is the boot session the run started in; a restore in
	// another boot changes nothing no journal entry names.
	runBoot string
}

// runner runs one command: argv (an absolute path first), stdin (nil:
// none).
type runner func(ctx context.Context, argv []string, stdin []byte) output

// run runs argv through h's runner.
func (h *host) run(ctx context.Context, argv []string, stdin []byte) output {
	if h.exec != nil {
		return h.exec(ctx, argv, stdin)
	}
	return run(ctx, argv, stdin)
}

func (h *host) log(format string, a ...any) {
	if h.logf != nil {
		h.logf(format, a...)
	}
}

// commandTimeout bounds every command the core runs.
const commandTimeout = 30 * time.Second

// output is what one command printed. Err says it couldn't run or didn't
// finish in time; an exit status is only Code.
type output struct {
	Stdout, Stderr []byte
	Code           int
	Err            string
}

// run runs argv (an absolute path first) with stdin (nil: none), in the C
// locale, bounded by commandTimeout, in a process group of its own: a
// signal for the terminal's group (Ctrl-C, Ctrl-Z) never reaches a pfctl
// in the middle of a load.
func run(ctx context.Context, argv []string, stdin []byte) output {
	if err := execGuard(argv[0]); err != nil {
		return output{Code: -1, Err: err.Error()}
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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
	case err != nil && !errors.As(err, new(*exec.ExitError)):
		out.Err = fmt.Sprintf("%s: %v", strings.Join(argv, " "), err)
	}
	return out
}

// execGuard may refuse a command before it runs: the core's tests refuse
// every host tool outside the lab, so no test, nor a mutant of one, runs
// pfctl or tcpdump on a developer's Mac. Nothing is refused in a run.
var execGuard = func(string) error { return nil }

// checked is nil for a command that ran and exited 0, else why not.
func checked(out output) error {
	switch {
	case out.Err != "":
		return errors.New(out.Err)
	case out.Code != 0:
		return fmt.Errorf("exit %d: %s", out.Code, strings.Join(listingLines(out.Stderr), "; "))
	}
	return nil
}

// outputLines are a successful listing's lines (listingLines).
func outputLines(out output) ([]string, error) {
	if err := checked(out); err != nil {
		return nil, err
	}
	return listingLines(out.Stdout), nil
}

// engine applies changes through the journal: nothing changes on the host
// without a restore plan for it.
type engine struct {
	h *host
	j *journal
	// armed says the dead-man is watching.
	armed func() error
}

// errNoRestorePlan: a change was refused before anything changed, because
// what would put the host back isn't in place.
var errNoRestorePlan = errors.New("refused: no restore plan")

// refuseChanges is a restore's armed: a restore makes no new change.
func refuseChanges() error { return errors.New("a restore makes no change") }

// do applies spec: refused unless the baseline is taken, the dead-man is
// armed and the change's undo is synced to the journal first. A change
// that fails is undone at once.
func (e *engine) do(ctx context.Context, spec Spec) (int, error) {
	if e.h.baseline == nil {
		return 0, fmt.Errorf("%w: no baseline of the host yet", errNoRestorePlan)
	}
	if err := e.armed(); err != nil {
		return 0, fmt.Errorf("%w: the dead-man: %w", errNoRestorePlan, err)
	}
	a, err := decode(spec)
	if err != nil {
		return 0, err
	}
	if err := a.pre(ctx, e.h); err != nil {
		return 0, fmt.Errorf("%s: refused: %w", a.does(), err)
	}
	seq, err := e.j.intent(a, spec.Params)
	if err != nil {
		return 0, fmt.Errorf("%w: the journal: %w", errNoRestorePlan, err)
	}
	learnt := func(params json.RawMessage) error { return e.j.mark(seq, stateApplied, params, nil) }
	if err := a.apply(ctx, e.h, learnt); err != nil {
		e.h.log("%s failed: %v; undoing it", a.does(), err)
		_, uerr := e.undo(ctx, e.entry(seq))
		return seq, errors.Join(err, uerr)
	}
	return seq, e.j.mark(seq, stateApplied, nil, nil)
}

// undoLast undoes the newest change still on the host and says what its
// undo did, as a restore's Undone does. A capture isn't a plan's to undo:
// it ends with the run.
func (e *engine) undoLast(ctx context.Context) (string, error) {
	p := e.j.pending()
	if len(p) == 0 {
		return "", errors.New("nothing to undo")
	}
	if p[0].Kind == kindCapture {
		return "", errors.New("the newest change is a capture: a capture ends with the run")
	}
	what, err := e.undo(ctx, p[0])
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%d: %s: %s", p[0].Seq, p[0].Does, what), nil
}

func (e *engine) entry(seq int) entry {
	for _, en := range e.j.entries() {
		if en.Seq == seq {
			return en
		}
	}
	return entry{Seq: seq}
}

// undo undoes one journaled change and says what it did. A volatile
// change of an earlier boot isn't assumed gone with that boot: its undo
// checks it is, changing nothing in this boot, and it is journaled
// gone-with-reboot only then.
func (e *engine) undo(ctx context.Context, en entry) (string, error) {
	laterBoot := en.Boot != e.h.boot
	a, err := decode(Spec{Kind: en.Kind, Params: en.Params})
	what := ""
	if err == nil {
		what, err = a.undo(ctx, e.h, laterBoot)
	}
	e.h.beat()
	if err != nil {
		return "", errors.Join(fmt.Errorf("undo %d (%s): %w", en.Seq, en.Does, err), e.j.mark(en.Seq, stateUndoFailed, nil, err))
	}
	s := stateUndone
	if laterBoot && en.Lifetime == volatile {
		s = stateGoneWithBoot
	}
	return what, e.j.mark(en.Seq, s, nil, nil)
}
