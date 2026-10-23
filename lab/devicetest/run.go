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
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
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
	// deadmanWait is how long a run with no answer from its helper waits
	// for the dead-man's result (default deadmanResultWait).
	deadmanWait time.Duration
}

// verdictUnknown: neither the helper nor the dead-man gave a result.
const verdictUnknown = "UNKNOWN"

// deadmanResultWait is how long the user side waits for the dead-man's
// result when the helper gave none: it notices a gone helper within a
// second, and its restore reads every surface once more.
const deadmanResultWait = 2 * time.Minute

func cmdRun(ctx context.Context, args []string) error {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return errors.New("which plan? (devicetest plans)")
	}
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	iface := fs.String("iface", "", "the physical interface (default: the IPv4 default route's)")
	thinkpol := fs.String("thinkpol", "", "a thinkpol binary: `thinkpol diag` is saved after each step")
	base := fs.String("evidence", "", "where evidence folders go (default ~/thinkpol-evidence)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	p, ok := plan.Lookup(allPlans(), args[0])
	if !ok {
		return fmt.Errorf("no plan for %s (devicetest plans)", args[0])
	}
	if err := p.Validate(); err != nil {
		return err
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
	ListingHash  string         `json:"listing_sha256"`
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
	ev.WriteFile("plan.txt", []byte(list))
	answer, err := ev.Ask(r.in, "Type yes to run it (sudo asks for your password next):")
	if err != nil || answer != "yes" {
		ev.Logf("not run: nothing changed")
		return err
	}
	rec := r.record(list, start)
	if err := r.startHelper(); err != nil {
		ev.Logf("the helper didn't start: %v; nothing changed", err)
		return errReported
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
	if res == nil {
		res = r.resultFromEvidence()
	}
	rec.Restore, rec.Ended = res, time.Now().UTC()
	ev.WriteJSON("run.json", rec)
	r.report(*res, rerr, steps, rec.SelfTest)
	if err != nil || rerr != nil || res.Verdict != safety.Clean {
		return errReported
	}
	return nil
}

// resultFromEvidence is the newest restore result in the evidence: the
// dead-man's, when the helper was killed, waited for up to deadmanWait;
// else UNKNOWN.
func (r *runner) resultFromEvidence() *safety.Result {
	wait := r.deadmanWait
	if wait == 0 {
		wait = deadmanResultWait
	}
	r.ev.Logf("the helper gave no result: waiting up to %v for its dead-man's", wait)
	for deadline := time.Now().Add(wait); ; time.Sleep(500 * time.Millisecond) {
		m, _ := filepath.Glob(filepath.Join(r.ev.Path, "restore", "result-*.json"))
		slices.Sort(m) // named by the time they were written
		if len(m) > 0 {
			var res safety.Result
			if b, err := os.ReadFile(m[len(m)-1]); err == nil && json.Unmarshal(b, &res) == nil {
				return &res
			}
		}
		if time.Now().After(deadline) {
			break
		}
	}
	return &safety.Result{Verdict: verdictUnknown, By: fmt.Sprintf("nobody: the helper gave no result, nor its dead-man within %v", wait),
		Notes: []string{"run devicetest restore"}}
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
	return runRecord{Ticket: r.plan.Ticket, Title: r.plan.Title, Run: r.runID, ListingHash: hex.EncodeToString(sum[:]),
		Tool: tool, SafetyFrozen: safety.FrozenSum(), OS: runtime.GOOS + "/" + runtime.GOARCH, Kernel: kernel,
		Physical: r.phys, Budget: r.plan.Budget.String(), Started: start.UTC()}
}

func (r *runner) startHelper() error {
	args := []string{"helper", "-run", r.runID, "-evidence", r.ev.Path, "-uid", strconv.Itoa(os.Getuid()),
		"-gid", strconv.Itoa(os.Getgid()), "-budget", r.plan.Budget.String()}
	mk := r.helperCommand
	if mk == nil {
		root, err := rootBinary()
		if err != nil {
			return err
		}
		mk = func(args []string) (*exec.Cmd, error) { return safety.RootCommand(root, args) }
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
		r.ev.AppendJSONL("captures/markers.jsonl", map[string]any{"time": time.Now().UTC(), "step": st.Name, "event": "start"})
		err := r.step(ctx, dir, st)
		r.ev.AppendJSONL("captures/markers.jsonl", map[string]any{"time": time.Now().UTC(), "step": st.Name, "event": "end"})
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
	case plan.OpRead:
		name := fmt.Sprintf("%s/cmd-%03d.%s", dir, n, slug(op.Argv))
		resp, err := r.c.call(safety.Request{Op: safety.OpRead, Argv: op.Argv, Name: name})
		r.ev.Logf("  root read: %s (exit %d) -> %s.out", strings.Join(op.Argv, " "), resp.Code, name)
		return err
	case plan.OpDo:
		spec, err := changeSpec(op.Change)
		if err != nil {
			return err
		}
		resp, err := r.c.call(safety.Request{Op: safety.OpDo, Change: &spec})
		r.ev.Logf("  change %d: %s", resp.Seq, describeOp(op))
		return err
	case plan.OpUndoLast:
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
		r.ev.WriteFile(dir+"/diag.error", []byte("not available: no -thinkpol binary given\n"))
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.thinkpol, "diag")
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil || len(out) == 0 {
		r.ev.WriteFile(dir+"/diag.error", fmt.Appendf(nil, "thinkpol diag: %v\n%s", err, stderr.String()))
		return
	}
	r.ev.WriteFile(dir+"/diag.json", out)
}

func (r *runner) report(res safety.Result, err error, steps int, selfTest string) {
	b, _ := json.MarshalIndent(res, "", "  ")
	r.ev.Logf("restore by %s:\n%s", res.By, b)
	if err != nil {
		r.ev.Logf("the restore reported: %v", err)
	}
	if res.Verdict != safety.Clean {
		r.ev.Logf("THE MAC ISN'T AS IT WAS (%s): %s", res.Verdict, stillPending(res.Run))
	}
	if selfTest != "ok" {
		selfTest = "FAILED"
	}
	recorded := "recorded"
	if n := r.ev.Failed(); n > 0 {
		recorded = fmt.Sprintf("INCOMPLETE (%d evidence files failed)", n)
	}
	r.ev.Logf("devicetest %s %s: %d of %d steps, selftest %s, restore %s -> %s",
		r.plan.Ticket, recorded, steps, len(r.plan.Steps), selfTest, res.Verdict, r.ev.Path)
}

// cmdRestore restores the run pending a restore from its journal, as
// root; with -forget RUN, closes that run in a later boot than its own.
func cmdRestore(args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	forget := fs.String("forget", "", "close the pending run RUN, in a later boot than its own")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 0 {
		return fmt.Errorf("restore takes no argument %q", fs.Arg(0))
	}
	rootArgs := []string{"root-restore"}
	if *forget != "" {
		rootArgs = append(rootArgs, "-forget", *forget)
	}
	root, err := rootBinary()
	if err != nil {
		return err
	}
	cmd, err := safety.RootCommand(root, rootArgs)
	if err != nil {
		return err
	}
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	return reportRestore(os.Stdout, out, err, *forget != "")
}

// closesRun says verdict v closes the run it names (the core's closes).
func closesRun(v string) bool {
	return v == safety.Clean || v == safety.Nothing || v == safety.ResetByReboot || v == safety.Forgotten
}

// stillPending says how a run left pending gets closed.
func stillPending(run string) string {
	name, forget := "run "+run, run
	if run == "" {
		name, forget = "the run", "RUN (the run devicetest restore names)"
	}
	return fmt.Sprintf("do what each item's \"next\" says, then run devicetest restore again. %s stays pending, and no run starts, "+
		"until a restore says CLEAN, or RESET-BY-REBOOT when run after a reboot; if it still says LEFT or REBOOT after a reboot, "+
		"devicetest restore -forget %s closes it (FORGOTTEN, never CLEAN)", name, forget)
}

// reportRestore prints root-restore's answer (out) for the owner: the
// result, then what it means. CLEAN, nothing pending, RESET-BY-REBOOT and
// FORGOTTEN let the next run start, each said for what it is; any other
// verdict keeps the run pending and blocks the next.
func reportRestore(w io.Writer, out []byte, runErr error, forget bool) error {
	var resp safety.Response
	if jerr := json.Unmarshal(out, &resp); jerr != nil || resp.Result == nil {
		_, _ = w.Write(out)
		return errors.Join(fmt.Errorf("root-restore gave no result: %q", out), runErr)
	}
	res := resp.Result
	if res.Verdict != "" {
		b, _ := json.MarshalIndent(res, "", "  ")
		_, _ = fmt.Fprintf(w, "%s\n", b)
	}
	switch {
	case !resp.OK && closesRun(res.Verdict):
		_, _ = fmt.Fprintf(w, "devicetest restore: %s, run %s closed; one step after it failed: %s\n", res.Verdict, res.Run, resp.Err)
	case !resp.OK && forget:
		_, _ = fmt.Fprintf(w, "devicetest restore -forget failed: %s\n", resp.Err)
		_, _ = fmt.Fprintln(w, "if it fails this way after a reboot too, because the run's record or directory can't be opened, "+
			"see lab/devicetest/safety/doc.go, \"Verdicts\": the one case neither a restore nor -forget can close")
	case !resp.OK:
		_, _ = fmt.Fprintf(w, "devicetest restore failed: %s\n", resp.Err)
		if res.Run != "" {
			_, _ = fmt.Fprintf(w, "run %s stays pending; if a restore after a reboot fails like this again, "+
				"devicetest restore -forget %s closes it (FORGOTTEN, never CLEAN)\n", res.Run, res.Run)
		}
	case res.Verdict == safety.Clean:
		_, _ = fmt.Fprintf(w, "devicetest restore: CLEAN, run %s restored; a new run may start\n", res.Run)
		return nil
	case res.Verdict == safety.Nothing && res.Run != "":
		_, _ = fmt.Fprintf(w, "devicetest restore: %s, run %s closed: it made no change and had no baseline to compare with\n", res.Verdict, res.Run)
		return nil
	case res.Verdict == safety.Nothing:
		_, _ = fmt.Fprintf(w, "devicetest restore: %s, no run was pending; nothing was compared\n", res.Verdict)
		return nil
	case res.Verdict == safety.ResetByReboot:
		_, _ = fmt.Fprintf(w, "devicetest restore: %s, run %s closed: every change it made was undone or went with its boot; "+
			"the Mac wasn't shown equal to its baseline (see \"left\": this boot's differences); a new run may start\n", res.Verdict, res.Run)
		return nil
	case res.Verdict == safety.Forgotten:
		_, _ = fmt.Fprintf(w, "devicetest restore: %s, run %s closed at your request; nothing was proven (see the notes and \"left\"); "+
			"a new run may start\n", res.Verdict, res.Run)
		return nil
	default:
		_, _ = fmt.Fprintf(w, "THE MAC ISN'T AS IT WAS (%s): %s\n", res.Verdict, stillPending(res.Run))
	}
	return errReported
}
