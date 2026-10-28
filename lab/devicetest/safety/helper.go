//go:build darwin || linux

package safety

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// Request is one line the user side sends the helper.
type Request struct {
	ID int    `json:"id"`
	Op string `json:"op"`
	// Name is the evidence file's base for a read's output, or the name
	// of a capture's copy.
	Name      string   `json:"name,omitempty"`
	Argv      []string `json:"argv,omitempty"`
	Change    *Spec    `json:"change,omitempty"`
	Iface     string   `json:"iface,omitempty"`
	Filter    string   `json:"filter,omitempty"`
	Nonce     string   `json:"nonce,omitempty"`
	TimeoutMS int      `json:"timeout_ms,omitempty"`
}

// The helper's operations.
const (
	OpRead         = "read"          // a root read (rootRead), its output saved
	OpDo           = "do"            // a change, through the journal
	OpUndoLast     = "undo_last"     // undo the newest change now (never a capture)
	OpCaptureStart = "capture_start" // a capture (a change)
	OpCaptureSeen  = "capture_seen"  // did a capture see a marker's nonce
	OpCutStart     = "cut_start"     // start a copy of a capture's stream
	OpCutEnd       = "cut_end"       // end it at a record's end
	OpRestore      = "restore"       // restore and end the run
)

// Response is the helper's answer to a request (ID 0: to its start).
type Response struct {
	ID   int    `json:"id"`
	OK   bool   `json:"ok"`
	Err  string `json:"err,omitempty"`
	Code int    `json:"code,omitempty"`
	Seq  int    `json:"seq,omitempty"`
	Seen bool   `json:"seen,omitempty"`
	// Did is what an undo_last's undo did.
	Did    string  `json:"did,omitempty"`
	Result *Result `json:"result,omitempty"`
}

// helperConfig is a run's helper.
type helperConfig struct {
	state    stateConfig
	run      string
	evidence string
	uid, gid int
	// budget is the dead-man's deadline.
	budget   time.Duration
	rootCopy string
	in       io.Reader
	out      io.Writer
	log      io.Writer
}

// errNotStarted wraps why a helper refused a run before it became pending
// (before its active pointer): a bad flag, the lock held, a run pending,
// the evidence folder, or its directory, record or journal failing. The
// caller removes its root copy; a run directory made before the failure
// stays, with no pointer to it, and is pruned like any old run.
var errNotStarted = errors.New("the run didn't start")

// helper runs a run's root side: it starts the run (journal, dead-man,
// baseline), answers the user side's requests, and restores when asked or
// when its input ends (the user side was closed or killed). It ignores
// the terminal's signals: a Ctrl-C reaches the user side, which asks for
// the restore, and never cuts a restore short.
func helper(ctx context.Context, cfg helperConfig) error {
	signal.Ignore(syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT)
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE) // a gone reader is a write error, not death
	enc := json.NewEncoder(cfg.out)
	r, err := startRun(ctx, cfg)
	if err != nil {
		_ = enc.Encode(Response{Err: err.Error()})
		return answered(err)
	}
	_ = enc.Encode(Response{OK: true})
	by := "the helper: its user side is gone (input ended)"
	last := 0
	sc := bufio.NewScanner(cfg.in)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var req Request
		if err := json.Unmarshal(sc.Bytes(), &req); err != nil {
			_ = enc.Encode(Response{Err: "unreadable request: " + err.Error()})
			continue
		}
		if req.Op == OpRestore {
			by, last = "the helper: asked", req.ID
			break
		}
		_ = enc.Encode(r.serve(ctx, req))
	}
	res := r.engine.restore(ctx, by)
	err = finish(r.state, r.openedRun, &res)
	resp := Response{ID: last, OK: err == nil, Result: &res}
	if err != nil {
		resp.Err = err.Error()
	}
	_ = enc.Encode(resp)
	return answered(err)
}

type runState struct {
	openedRun
	state  *os.File
	lock   *os.File
	engine *engine
}

// startRun starts a run: refused while another helper runs or a run is
// pending a restore; then the old runs pruned, the run's directory, its
// record, its journal and the active pointer, then the dead-man (armed
// before any snapshot or change) and the baseline. A run refused once it
// is pending (the dead-man or the baseline failing) ends through finish,
// NOTHING-TO-RESTORE; one refused before is errNotStarted.
func startRun(ctx context.Context, cfg helperConfig) (*runState, error) {
	r, err := openRunState(cfg)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errNotStarted, err)
	}
	if err := r.armAndBaseline(ctx, cfg); err != nil {
		res := Result{Verdict: Nothing, By: "the helper", Notes: []string{"the run didn't start: " + err.Error()}}
		return nil, errors.Join(err, finish(r.state, r.openedRun, &res))
	}
	return r, nil
}

func openRunState(cfg helperConfig) (*runState, error) {
	if s := os.Getenv("SUDO_UID"); s != "" && s != strconv.Itoa(cfg.uid) {
		return nil, fmt.Errorf("-uid %d is not sudo's caller (%s)", cfg.uid, s)
	}
	if !runID.MatchString(cfg.run) {
		return nil, fmt.Errorf("bad run id %q", cfg.run)
	}
	state, err := cfg.state.open()
	if err != nil {
		return nil, err
	}
	lk, err := trusteddir.Lock(state, lockFile)
	if err != nil {
		return nil, fmt.Errorf("another devicetest helper runs: %w", err)
	}
	run, err := pendingRun(state)
	if err != nil {
		return nil, fmt.Errorf("the run pending a restore: %w", err)
	}
	if run != "" {
		return nil, fmt.Errorf("run %q is pending a restore: run `devicetest restore` first", run)
	}
	ev, err := openEvidence(cfg.evidence, cfg.uid, cfg.gid)
	if err != nil {
		return nil, fmt.Errorf("the evidence folder: %w", err)
	}
	r := &runState{state: state, lock: lk}
	if err := prune(state); err != nil {
		_, _ = fmt.Fprintf(cfg.logWriter(), "helper: pruning old runs: %v\n", err)
	}
	return r, r.open(cfg, ev)
}

func (cfg helperConfig) logWriter() io.Writer {
	if cfg.log == nil {
		return io.Discard
	}
	return cfg.log
}

// open makes the run's directory, its record and its journal (synced),
// and only then the active pointer: it never names a run with no journal.
func (r *runState) open(cfg helperConfig, ev *evidence) error {
	boot, err := trusteddir.BootSession()
	if err != nil {
		return err
	}
	if err := unix.Mkdirat(int(r.state.Fd()), "run-"+cfg.run, 0o700); err != nil {
		return fmt.Errorf("the run's directory: %w", err)
	}
	runDir, err := trusteddir.Open(filepath.Join(cfg.state.dir, "run-"+cfg.run))
	if err != nil {
		return err
	}
	r.info = runInfo{Run: cfg.run, Evidence: ev.path(), UID: cfg.uid, GID: cfg.gid, RootCopy: cfg.rootCopy, Boot: boot, Started: time.Now().UTC()}
	b, _ := json.MarshalIndent(r.info, "", "  ")
	if err := trusteddir.WriteFile(runDir, runInfoFile, b); err != nil {
		return err
	}
	if r.j, err = createJournal(runDir, cfg.run, boot); err != nil {
		return err
	}
	if err := errors.Join(trusteddir.WriteFile(r.state, activeFile, []byte(cfg.run+"\n")), fullSync(r.state)); err != nil {
		return err
	}
	logf := func(format string, a ...any) { _, _ = fmt.Fprintf(cfg.logWriter(), "helper: "+format+"\n", a...) }
	r.h = &host{runDir: runDir, evidence: ev, boot: boot, runBoot: boot, surfaces: cfg.state.surfaces, exec: cfg.state.exec,
		captures: &captures{live: map[string]*liveCapture{}, ev: ev}, logf: logf}
	r.engine = &engine{h: r.h, j: r.j, armed: func() error { return armed(runDir) }}
	return nil
}

// armAndBaseline starts the dead-man in a session of its own (nothing that
// signals the run's process group or terminal reaches it), waits for it
// to be armed, and takes the baseline. A baseline that can't read a
// surface it compares stops the run before anything changes: no restore
// could ever show the host equal to it.
func (r *runState) armAndBaseline(ctx context.Context, cfg helperConfig) error {
	start, err := startTime(os.Getpid())
	if err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "deadman", "-run", cfg.run, "-helper-pid", strconv.Itoa(os.Getpid()),
		"-helper-start", strconv.FormatInt(start, 10), "-deadline", cfg.budget.String())
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("the dead-man: %w", err)
	}
	go func() { _ = cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for armed(r.h.runDir) != nil {
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			return errors.New("the dead-man didn't arm within 10 s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	base, err := r.h.snapshot(ctx, baselineName)
	if err != nil {
		return fmt.Errorf("the baseline: %w", err)
	}
	if err := unreadableCompared(r.h.surfaceList(), base); err != nil {
		return err
	}
	r.h.baseline = base
	return nil
}

func (r *runState) serve(ctx context.Context, req Request) Response {
	resp := Response{ID: req.ID}
	var err error
	switch req.Op {
	case OpRead:
		resp.Code, err = r.read(ctx, req)
	case OpDo:
		if req.Change == nil {
			err = errors.New("no change")
			break
		}
		resp.Seq, err = r.engine.do(ctx, *req.Change)
	case OpUndoLast:
		resp.Did, err = r.engine.undoLast(ctx)
	case OpCaptureStart:
		params, _ := json.Marshal(captureAction{Iface: req.Iface, Filter: req.Filter})
		resp.Seq, err = r.engine.do(ctx, Spec{Kind: kindCapture, Params: params})
	case OpCaptureSeen, OpCutStart, OpCutEnd:
		resp.Seen, err = r.capture(ctx, req)
	default:
		err = fmt.Errorf("no operation %q", req.Op)
	}
	resp.OK = err == nil
	if err != nil {
		resp.Err = err.Error()
	}
	return resp
}

func (r *runState) read(ctx context.Context, req Request) (int, error) {
	argv, err := rootRead(req.Argv)
	if err != nil {
		return 0, err
	}
	out := r.h.run(ctx, argv, nil)
	r.h.saveOutput(req.Name, argv, out)
	return out.Code, checked(out)
}

func (r *runState) capture(ctx context.Context, req Request) (bool, error) {
	c, err := r.h.captures.get(req.Iface)
	if err != nil {
		return false, err
	}
	switch req.Op {
	case OpCaptureSeen:
		return c.seen(ctx, req.Nonce, time.Duration(req.TimeoutMS)*time.Millisecond), nil
	case OpCutStart:
		return false, c.cutStart(r.h.evidence, req.Name)
	default:
		return false, c.cutEnd()
	}
}
