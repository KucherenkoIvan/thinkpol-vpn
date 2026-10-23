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
	// Name is the evidence file's base for a read's output, or a
	// snapshot's or cut's name.
	Name      string   `json:"name,omitempty"`
	Argv      []string `json:"argv,omitempty"`
	Action    *Spec    `json:"action,omitempty"`
	Iface     string   `json:"iface,omitempty"`
	Filter    string   `json:"filter,omitempty"`
	Nonce     string   `json:"nonce,omitempty"`
	TimeoutMS int      `json:"timeout_ms,omitempty"`
}

// The helper's operations.
const (
	OpRead         = "read"          // a root read (RootRead), its output saved
	OpDo           = "do"            // an action, through the journal
	OpUndoLast     = "undo_last"     // undo the newest action now
	OpCaptureStart = "capture_start" // a capture (an action)
	OpCaptureSeen  = "capture_seen"  // did a capture see a marker's nonce
	OpCutStart     = "cut_start"     // start a copy of a capture's stream
	OpCutEnd       = "cut_end"       // end it at a record's end
	OpSnapshot     = "snapshot"      // a snapshot of the host
	OpRestore      = "restore"       // restore and end the run
)

// Response is the helper's answer to a request (ID 0: to its start).
type Response struct {
	ID     int     `json:"id"`
	OK     bool    `json:"ok"`
	Err    string  `json:"err,omitempty"`
	Code   int     `json:"code,omitempty"`
	Stdout string  `json:"stdout,omitempty"`
	Seq    int     `json:"seq,omitempty"`
	Seen   bool    `json:"seen,omitempty"`
	Run    string  `json:"run,omitempty"`
	Result *Result `json:"result,omitempty"`
}

// stdoutMax is how much of a read's output a response carries; the file
// has all of it.
const stdoutMax = 64 << 10

// HelperConfig is a run's helper.
type HelperConfig struct {
	State    StateConfig
	Run      string
	Evidence string
	UID, GID int
	// Budget is the dead-man's deadline.
	Budget   time.Duration
	RootCopy string
	// DeadmanCommand makes the dead-man's process from its arguments
	// (default: this binary's "deadman" mode).
	DeadmanCommand func(args []string) (*exec.Cmd, error)
	In             io.Reader
	Out            io.Writer
	Log            io.Writer
}

// Helper runs a run's root side: it starts the run (journal, dead-man,
// baseline), answers the user side's requests, and restores when asked or
// when its input ends (the user side was closed or killed). It ignores
// the terminal's signals: a Ctrl-C reaches the user side, which asks for
// the restore, and never cuts a restore short.
func Helper(ctx context.Context, cfg HelperConfig) error {
	signal.Ignore(syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGQUIT)
	signal.Notify(make(chan os.Signal, 1), syscall.SIGPIPE) // a gone reader is a write error, not death
	enc := json.NewEncoder(cfg.Out)
	r, err := startRun(ctx, cfg)
	if err != nil {
		_ = enc.Encode(Response{Err: err.Error()})
		return err
	}
	_ = enc.Encode(Response{OK: true, Run: cfg.Run})
	by := "the helper: its user side is gone (input ended)"
	last := 0
	sc := bufio.NewScanner(cfg.In)
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
	res := r.engine.Restore(ctx, by)
	err = finish(r.state, r.h, r.j, r.info, res)
	resp := Response{ID: last, OK: err == nil, Result: &res}
	if err != nil {
		resp.Err = err.Error()
	}
	_ = enc.Encode(resp)
	return err
}

type runState struct {
	state  *os.File
	lock   *os.File
	h      *Host
	j      *Journal
	engine *Engine
	info   runInfo
}

// startRun starts a run: refused while another helper runs or a run is
// unfinished; then the run's directory, the active pointer, the journal,
// the dead-man (armed before anything else) and the baseline.
func startRun(ctx context.Context, cfg HelperConfig) (*runState, error) {
	if err := cfg.checkUser(); err != nil {
		return nil, err
	}
	state, err := cfg.State.open()
	if err != nil {
		return nil, err
	}
	lk, err := trusteddir.Lock(state, lockFile)
	if err != nil {
		return nil, fmt.Errorf("another devicetest helper runs: %w", err)
	}
	if run, err := cfg.State.Active(); err != nil || run != "" {
		return nil, fmt.Errorf("run %s did not finish restoring: run `devicetest restore` first (%v)", run, err)
	}
	ev, err := OpenEvidence(cfg.Evidence, cfg.UID, cfg.GID)
	if err != nil {
		return nil, fmt.Errorf("the evidence folder: %w", err)
	}
	r := &runState{state: state, lock: lk}
	if err := r.open(cfg, ev); err != nil {
		return nil, err
	}
	if err := r.armAndBaseline(ctx, cfg); err != nil {
		res := Result{Verdict: Clean, By: "the helper: the run didn't start", Notes: []string{err.Error()}}
		return nil, errors.Join(err, finish(state, r.h, r.j, r.info, res))
	}
	return r, nil
}

// checkUser checks the evidence's user is sudo's caller, when sudo ran it.
func (cfg HelperConfig) checkUser() error {
	if s := os.Getenv("SUDO_UID"); s != "" && s != strconv.Itoa(cfg.UID) {
		return fmt.Errorf("-uid %d is not sudo's caller (%s)", cfg.UID, s)
	}
	return nil
}

func (r *runState) open(cfg HelperConfig, ev *Evidence) error {
	boot, err := bootSession()
	if err != nil {
		return err
	}
	if !runID.MatchString(cfg.Run) {
		return fmt.Errorf("bad run id %q", cfg.Run)
	}
	if err := unix.Mkdirat(int(r.state.Fd()), "run-"+cfg.Run, 0o700); err != nil {
		return fmt.Errorf("the run's directory: %w", err)
	}
	runDir, err := trusteddir.Open(filepath.Join(cfg.State.Dir, "run-"+cfg.Run))
	if err != nil {
		return err
	}
	r.info = runInfo{Run: cfg.Run, Evidence: ev.Path(), UID: cfg.UID, GID: cfg.GID, RootCopy: cfg.RootCopy, Boot: boot, Started: time.Now().UTC()}
	b, _ := json.MarshalIndent(r.info, "", "  ")
	if err := trusteddir.WriteFile(runDir, runInfoFile, b); err != nil {
		return err
	}
	if err := trusteddir.WriteFile(r.state, activeFile, []byte(cfg.Run+"\n")); err != nil {
		return err
	}
	if err := unix.Fsync(int(r.state.Fd())); err != nil {
		return err
	}
	j, err := CreateJournal(runDir, cfg.Run, boot)
	if err != nil {
		_ = trusteddir.Remove(r.state, activeFile)
		return err
	}
	logf := func(format string, a ...any) {
		if cfg.Log != nil {
			_, _ = fmt.Fprintf(cfg.Log, "helper: "+format+"\n", a...)
		}
	}
	r.j = j
	r.h = &Host{RunDir: runDir, Evidence: ev, Boot: boot, Surfaces: cfg.State.Surfaces,
		captures: &captures{live: map[string]*liveCapture{}, ev: ev}, logf: logf}
	r.engine = NewEngine(r.h, j, func() error { return armed(runDir) })
	return nil
}

// armAndBaseline starts the dead-man, waits for it to be armed, and takes
// the baseline.
func (r *runState) armAndBaseline(ctx context.Context, cfg HelperConfig) error {
	args := []string{"deadman", "-run", cfg.Run, "-helper-pid", strconv.Itoa(os.Getpid()), "-deadline", cfg.Budget.String()}
	mk := cfg.DeadmanCommand
	if mk == nil {
		mk = selfCommand
	}
	cmd, err := mk(args)
	if err != nil {
		return err
	}
	// A session of its own: nothing that signals the run's process group
	// or terminal reaches it.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("the dead-man: %w", err)
	}
	go func() { _ = cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for armed(r.h.RunDir) != nil {
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			return errors.New("the dead-man didn't arm within 10 s")
		}
		time.Sleep(50 * time.Millisecond)
	}
	base, err := r.h.Snapshot(ctx, "00-baseline")
	if err != nil {
		return fmt.Errorf("the baseline: %w", err)
	}
	r.h.Baseline = base
	return nil
}

func selfCommand(args []string) (*exec.Cmd, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, err
	}
	return exec.Command(self, args...), nil
}

func (r *runState) serve(ctx context.Context, req Request) Response {
	resp := Response{ID: req.ID}
	var err error
	switch req.Op {
	case OpRead:
		resp, err = r.read(ctx, req)
	case OpDo:
		if req.Action == nil {
			err = errors.New("no action")
			break
		}
		resp.Seq, err = r.engine.Do(ctx, *req.Action)
	case OpUndoLast:
		err = r.engine.UndoLast(ctx)
	case OpCaptureStart:
		params, _ := json.Marshal(CaptureAction{Iface: req.Iface, Filter: req.Filter})
		resp.Seq, err = r.engine.Do(ctx, Spec{Kind: KindCapture, Params: params})
	case OpCaptureSeen, OpCutStart, OpCutEnd:
		resp, err = r.capture(ctx, req)
	case OpSnapshot:
		_, err = r.h.Snapshot(ctx, req.Name)
	default:
		err = fmt.Errorf("no operation %q", req.Op)
	}
	resp.ID, resp.OK = req.ID, err == nil
	if err != nil {
		resp.Err = err.Error()
	}
	return resp
}

func (r *runState) read(ctx context.Context, req Request) (Response, error) {
	argv, err := RootRead(req.Argv)
	if err != nil {
		return Response{}, err
	}
	out := run(ctx, argv, nil)
	r.h.saveOutput(req.Name, argv, out)
	resp := Response{Code: out.Code, Stdout: string(out.Stdout[:min(len(out.Stdout), stdoutMax)])}
	if out.Err != "" {
		return resp, errors.New(out.Err)
	}
	return resp, nil
}

func (r *runState) capture(ctx context.Context, req Request) (Response, error) {
	c, err := r.h.captures.get(req.Iface)
	if err != nil {
		return Response{}, err
	}
	switch req.Op {
	case OpCaptureSeen:
		return Response{Seen: c.Seen(ctx, req.Nonce, time.Duration(req.TimeoutMS)*time.Millisecond)}, nil
	case OpCutStart:
		return Response{}, c.cutStart(r.h.Evidence, req.Name)
	default:
		return Response{}, c.cutEnd()
	}
}
