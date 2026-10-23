//go:build darwin || linux

package main

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/evidence"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/plan"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/devicetest/safety"
)

// runner runs one plan: the self-test, the steps, the restore.
type runner struct {
	plan     plan.Plan
	phys     string
	thinkpol string
	in       *bufio.Reader
	out      io.Writer
	ev       *evidence.Folder
	c        *client
	runID    string
	stopped  atomic.Bool
	// helperCommand makes the helper's command (default: the launch
	// script under sudo); the lab's tests run it as root without sudo.
	helperCommand func(args []string) (*exec.Cmd, error)
}

func cmdRun(ctx context.Context, args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("which plan? (devicetest plans)")
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	iface := fs.String("iface", "", "the physical interface (default: the IPv4 default route's)")
	thinkpol := fs.String("thinkpol", "", "a thinkpol binary: `thinkpol diag` is saved after each step")
	base := fs.String("evidence", "", "where evidence folders go (default ~/thinkpol-evidence)")
	config := fs.String("config", "", "the private config file (read only by plans that need the exit server)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	p, ok := plan.Lookup(args[0])
	if !ok {
		return fmt.Errorf("no plan for %s (devicetest plans)", args[0])
	}
	if p.NeedsExit {
		if _, err := loadPrivateConfig(*config); err != nil {
			return err
		}
		return errors.New("this plan needs the exit server, and the exit driver isn't built yet")
	}
	phys := *iface
	if phys == "" {
		var err error
		if phys, err = physicalInterface(); err != nil {
			return fmt.Errorf("the physical interface: %w (give it with -iface)", err)
		}
	}
	if *base == "" {
		var err error
		if *base, err = evidence.DefaultBase(); err != nil {
			return err
		}
	}
	r := &runner{plan: p, phys: phys, thinkpol: *thinkpol, in: bufio.NewReader(os.Stdin), out: os.Stdout}
	return r.run(ctx, *base)
}

// runRecord is run.json: what ran, on what, and how it ended.
type runRecord struct {
	Ticket       string         `json:"ticket"`
	Title        string         `json:"title"`
	Run          string         `json:"run"`
	PlanSHA256   string         `json:"plan_sha256"`
	Tool         string         `json:"tool"`
	SafetyFrozen string         `json:"safety_frozen_sha256"`
	OS           string         `json:"os"`
	Kernel       string         `json:"kernel"`
	Physical     string         `json:"physical_interface"`
	Budget       string         `json:"budget"`
	Started      time.Time      `json:"started"`
	Ended        time.Time      `json:"ended"`
	SelfTest     string         `json:"selftest"`
	Steps        int            `json:"steps_recorded"`
	Stopped      string         `json:"stopped,omitempty"`
	Restore      *safety.Result `json:"restore,omitempty"`
}

func (r *runner) run(ctx context.Context, base string) error {
	list := listing(r.plan, r.phys)
	_, _ = fmt.Fprint(r.out, list)
	start := time.Now()
	ev, err := evidence.Create(base, r.plan.Ticket, start, r.out)
	if err != nil {
		return err
	}
	defer func() { _ = ev.Close() }()
	r.ev = ev
	_ = ev.WriteFile("plan.txt", []byte(list))
	answer, err := ev.Ask(r.in, "Type yes to run it (sudo asks for your password next):")
	if err != nil || answer != "yes" {
		ev.Logf("not run: nothing changed")
		return err
	}
	rec := r.record(list, start)
	if err := r.startHelper(); err != nil {
		ev.Logf("the helper didn't start: %v; nothing changed", err)
		return err
	}
	r.watchSignals()
	steps, err := 0, r.selfTest(ctx)
	rec.SelfTest = "ok"
	if err != nil {
		rec.SelfTest = err.Error()
		ev.Logf("SELF-TEST FAILED: %v; restoring (nothing of the plan's ran)", err)
	} else {
		steps, err = r.steps(ctx)
	}
	if err != nil {
		rec.Stopped = err.Error()
	}
	rec.Steps = steps
	res, rerr := r.c.restore()
	rec.Restore, rec.Ended = &res, time.Now().UTC()
	_ = ev.WriteJSON("run.json", rec)
	r.report(res, rerr, steps, rec.SelfTest)
	return errors.Join(err, rerr)
}

func (r *runner) record(list string, start time.Time) runRecord {
	sum := sha256.Sum256([]byte(list))
	tool := "unknown"
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				tool = s.Value
			}
		}
	}
	var u unix.Utsname
	kernel := ""
	if unix.Uname(&u) == nil {
		kernel = unix.ByteSliceToString(u.Release[:])
	}
	r.runID = start.UTC().Format("20060102T150405Z") + "-" + strings.ToLower(r.plan.Ticket)
	return runRecord{Ticket: r.plan.Ticket, Title: r.plan.Title, Run: r.runID, PlanSHA256: hex.EncodeToString(sum[:]),
		Tool: tool, SafetyFrozen: safety.FrozenSum(), OS: runtime.GOOS + "/" + runtime.GOARCH, Kernel: kernel,
		Physical: r.phys, Budget: r.plan.Budget.String(), Started: start.UTC()}
}

func (r *runner) startHelper() error {
	args := []string{"helper", "-run", r.runID, "-evidence", r.ev.Path, "-uid", strconv.Itoa(os.Getuid()),
		"-gid", strconv.Itoa(os.Getgid()), "-budget", r.plan.Budget.String()}
	mk := r.helperCommand
	if mk == nil {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		mk = func(args []string) (*exec.Cmd, error) { return safety.RootCommand(self, args) }
	}
	cmd, err := mk(args)
	if err != nil {
		return err
	}
	r.ev.Logf("starting the helper (root): journal, dead-man (deadline %v), baseline", r.plan.Budget)
	r.c, err = startClient(cmd)
	return err
}

// watchSignals: Ctrl-C stops the plan after the operation running now,
// and the restore runs; more Ctrl-Cs only say so. A closed terminal ends
// this side: the helper sees its input end and restores by itself.
func (r *runner) watchSignals() {
	ch := make(chan os.Signal, 4)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	go func() {
		for sig := range ch {
			if sig == syscall.SIGHUP {
				r.c.abandon()
				os.Exit(1)
			}
			if r.stopped.Swap(true) {
				r.ev.Logf("restoring, wait: a second Ctrl-C doesn't stop the restore")
				continue
			}
			r.ev.Logf("%v: stopping after the operation running now, then restoring", sig)
		}
	}()
}

var errStopped = errors.New("stopped by the owner")

// steps runs the plan's steps; it returns how many were recorded.
func (r *runner) steps(ctx context.Context) (int, error) {
	for i, st := range r.plan.Steps {
		dir := fmt.Sprintf("steps/%02d-%s", i+1, st.Name)
		r.ev.Logf("step %d %s", i+1, st.Name)
		_ = r.ev.AppendJSONL("captures/markers.jsonl", map[string]any{"time": time.Now().UTC(), "step": st.Name, "event": "start"})
		err := r.step(ctx, dir, st)
		_ = r.ev.AppendJSONL("captures/markers.jsonl", map[string]any{"time": time.Now().UTC(), "step": st.Name, "event": "end"})
		r.saveDiag(ctx, dir)
		if err != nil {
			return i, err
		}
	}
	return len(r.plan.Steps), nil
}

func (r *runner) step(ctx context.Context, dir string, st plan.Step) error {
	for j, op := range st.Ops {
		if r.stopped.Load() {
			return errStopped
		}
		err := r.op(dir, j+1, op)
		if err == nil {
			continue
		}
		r.ev.Logf("STOP: %s failed: %v", describeOp(op), err)
		answer, _ := r.ev.Ask(r.in, "The plan doesn't say what to do now. Type continue to go on, or press Enter to restore and end the run:")
		if answer != "continue" {
			return fmt.Errorf("%s: %w", describeOp(op), err)
		}
	}
	return nil
}

func (r *runner) op(dir string, n int, op plan.Op) error {
	switch op.Kind {
	case plan.RootRead:
		name := fmt.Sprintf("%s/cmd-%03d.%s", dir, n, slug(op.Argv))
		resp, err := r.c.call(safety.Request{Op: safety.OpRead, Argv: op.Argv, Name: name})
		r.ev.Logf("  root read: %s (exit %d) -> %s.out", strings.Join(op.Argv, " "), resp.Code, name)
		return err
	case plan.Do:
		spec, err := changeSpec(op.Change)
		if err != nil {
			return err
		}
		resp, err := r.c.call(safety.Request{Op: safety.OpDo, Action: &spec})
		r.ev.Logf("  change %d: %s", resp.Seq, describeOp(op))
		return err
	case plan.UndoNewest:
		_, err := r.c.call(safety.Request{Op: safety.OpUndoLast})
		r.ev.Logf("  undone: the newest change")
		return err
	}
	return fmt.Errorf("operation kind %d", op.Kind)
}

func changeSpec(c plan.Change) (safety.Spec, error) {
	params, err := json.Marshal(c.Params)
	return safety.Spec{Kind: c.Kind, Params: params}, err
}

// slug names a command's output files after its words.
func slug(argv []string) string {
	s := strings.Join(argv, "-")
	return strings.Map(func(c rune) rune {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == '_' {
			return c
		}
		return '_'
	}, s)
}

// saveDiag saves `thinkpol diag` after a step: its output, or why there is
// none (never an empty file).
func (r *runner) saveDiag(ctx context.Context, dir string) {
	if r.thinkpol == "" {
		_ = r.ev.WriteFile(dir+"/diag.error", []byte("not available: no -thinkpol binary given\n"))
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.thinkpol, "diag")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		_ = r.ev.WriteFile(dir+"/diag.error", fmt.Appendf(nil, "thinkpol diag: %v\n%s", err, stderr.String()))
		return
	}
	_ = r.ev.WriteFile(dir+"/diag.json", out)
}

func (r *runner) report(res safety.Result, err error, steps int, selfTest string) {
	b, _ := json.MarshalIndent(res, "", "  ")
	r.ev.Logf("restore by %s:\n%s", res.By, b)
	if err != nil {
		r.ev.Logf("the restore reported: %v", err)
	}
	if res.Verdict != safety.Clean {
		r.ev.Logf("THE MAC ISN'T AS IT WAS (%s): do what each item's \"next\" says, then run devicetest restore", res.Verdict)
	}
	if selfTest != "ok" {
		selfTest = "FAILED"
	}
	r.ev.Logf("devicetest %s recorded: %d of %d steps, selftest %s, restore %s -> %s",
		r.plan.Ticket, steps, len(r.plan.Steps), selfTest, res.Verdict, r.ev.Path)
}

// cmdRestore finishes an unfinished run from its journal, as root.
func cmdRestore() error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd, err := safety.RootCommand(self, []string{"root-restore"})
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	_, _ = os.Stdout.Write(out)
	return err
}
