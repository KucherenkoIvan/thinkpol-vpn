//go:build darwin || linux

package safety

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

func TestTheDeadmanWatches(t *testing.T) {
	type watched struct {
		fire bool
		why  string
		took time.Duration
	}
	watch := func(t *testing.T, dir *os.File, cfg DeadmanConfig) <-chan watched {
		out := make(chan watched, 1)
		start := time.Now()
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		go func() {
			defer cancel()
			fire, why := Watch(ctx, dir, cfg)
			if ctx.Err() != nil {
				why = "still watching after 10 s"
			}
			out <- watched{fire, why, time.Since(start)}
		}()
		return out
	}
	beat := func(dir *os.File, every time.Duration, until time.Duration) {
		n, stop := 0, time.Now().Add(until)
		for time.Now().Before(stop) {
			n++
			_ = trusteddir.WriteFile(dir, heartbeatFile, []byte(strconv.Itoa(n)))
			time.Sleep(every)
		}
	}
	fast := DeadmanConfig{Poll: 20 * time.Millisecond}

	t.Run("the helper killed", func(t *testing.T) {
		dir := openDir(t, tempDir(t))
		helper := startSleep(t)
		cfg := fast
		cfg.HelperPID, cfg.Deadline = helper.Process.Pid, time.Hour
		got := watch(t, dir, cfg)
		time.Sleep(100 * time.Millisecond)
		_ = helper.Process.Signal(syscall.SIGKILL)
		w := <-got
		if !w.fire || !strings.Contains(w.why, "helper is gone") {
			t.Errorf("%+v", w)
		}
	})
	t.Run("the stop file", func(t *testing.T) {
		dir := openDir(t, tempDir(t))
		cfg := fast
		cfg.HelperPID, cfg.Deadline = startSleep(t).Process.Pid, time.Hour
		got := watch(t, dir, cfg)
		if err := trusteddir.WriteFile(dir, stopFile, nil); err != nil {
			t.Fatal(err)
		}
		if w := <-got; w.fire {
			t.Errorf("fired: %+v", w)
		}
	})
	t.Run("the deadline without a restore", func(t *testing.T) {
		dir := openDir(t, tempDir(t))
		cfg := fast
		cfg.HelperPID, cfg.Deadline = startSleep(t).Process.Pid, 300*time.Millisecond
		w := <-watch(t, dir, cfg)
		if !w.fire || !strings.Contains(w.why, "deadline") || w.took < cfg.Deadline {
			t.Errorf("%+v", w)
		}
	})
	t.Run("a fresh heartbeat holds it until the cap", func(t *testing.T) {
		dir := openDir(t, tempDir(t))
		cfg := fast
		cfg.HelperPID, cfg.Deadline, cfg.Cap, cfg.Stale = startSleep(t).Process.Pid, 100*time.Millisecond, 1200*time.Millisecond, 300*time.Millisecond
		got := watch(t, dir, cfg)
		go beat(dir, 30*time.Millisecond, 5*time.Second)
		w := <-got
		if !w.fire || !strings.Contains(w.why, "cap") || w.took < cfg.Cap {
			t.Errorf("%+v", w)
		}
	})
	t.Run("a heartbeat that goes stale", func(t *testing.T) {
		dir := openDir(t, tempDir(t))
		cfg := fast
		cfg.HelperPID, cfg.Deadline, cfg.Cap, cfg.Stale = startSleep(t).Process.Pid, 100*time.Millisecond, time.Hour, 300*time.Millisecond
		got := watch(t, dir, cfg)
		beat(dir, 30*time.Millisecond, 600*time.Millisecond)
		w := <-got
		if !w.fire || !strings.Contains(w.why, "deadline") || w.took < 600*time.Millisecond+cfg.Stale {
			t.Errorf("%+v", w)
		}
	})
}

// helperRun is a helper started as a child of the test, as the user side
// starts one: its requests on stdin, its answers on stdout.
type helperRun struct {
	t        *testing.T
	cmd      *exec.Cmd
	in       io.WriteCloser
	out      *bufio.Scanner
	state    string
	evidence string
	surface  string
	run      string
	id       int
}

func startHelper(t *testing.T, state, evidence, surface, run string) (*helperRun, Response) {
	t.Helper()
	env := []string{stateEnv + "=" + state, surfaceEnv + "=" + surface, nonRootEnv + "=1"}
	cmd := childCommand(t, env, "helper", "-run", run, "-evidence", evidence,
		"-uid", strconv.Itoa(os.Getuid()), "-gid", strconv.Itoa(os.Getgid()), "-budget", "30s")
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); killDeadman(state, run) })
	h := &helperRun{t: t, cmd: cmd, in: in, out: bufio.NewScanner(stdout), state: state, evidence: evidence, surface: surface, run: run}
	return h, h.response()
}

func (h *helperRun) response() Response {
	h.t.Helper()
	if !h.out.Scan() {
		h.t.Fatalf("the helper said nothing: %v", h.out.Err())
	}
	var r Response
	if err := json.Unmarshal(h.out.Bytes(), &r); err != nil {
		h.t.Fatal(err)
	}
	return r
}

func (h *helperRun) ask(req Request) Response {
	h.t.Helper()
	h.id++
	req.ID = h.id
	b, _ := json.Marshal(req)
	if _, err := h.in.Write(append(b, '\n')); err != nil {
		h.t.Fatal(err)
	}
	return h.response()
}

func (h *helperRun) runDir() *os.File {
	return openDir(h.t, filepath.Join(h.state, "run-"+h.run))
}

// killDeadman stops a test's dead-man, if it still runs.
func killDeadman(state, run string) {
	b, err := os.ReadFile(filepath.Join(state, "run-"+run, armedFile))
	if err != nil {
		return
	}
	var pid int
	var start int64
	if _, err := fmt.Sscan(string(b), &pid, &start); err == nil && sameProcess(pid, start) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

func newHelperDirs(t *testing.T) (state, evidence, surface string) {
	base := tempDir(t)
	surface = filepath.Join(base, "surface.txt")
	writeFile(t, surface, "route a\n")
	evidence = filepath.Join(base, "evidence")
	if err := os.Mkdir(evidence, 0o700); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(base, "state"), evidence, surface
}

var runs atomic.Int32

func runName() string { return fmt.Sprintf("test-%d", runs.Add(1)) }

func TestTheHelperRestores(t *testing.T) {
	t.Run("when its input ends", func(t *testing.T) {
		state, evidence, surface := newHelperDirs(t)
		h, hello := startHelper(t, state, evidence, surface, runName())
		if !hello.OK {
			t.Fatalf("start: %+v", hello)
		}
		if r := h.ask(Request{Op: OpDo, Action: ptr(fileSpec("one", "1"))}); !r.OK {
			t.Fatalf("do: %+v", r)
		}
		dir := h.runDir()
		if !present(dir, "file-one") {
			t.Fatal("the change wasn't made")
		}
		_ = h.in.Close()
		end := h.response()
		if !end.OK || end.Result == nil || end.Result.Verdict != Clean || present(dir, "file-one") {
			t.Fatalf("after the input ended: %+v %+v", end, end.Result)
		}
		assertClosed(t, h)
	})
	t.Run("after a Ctrl-C, only when asked", func(t *testing.T) {
		state, evidence, surface := newHelperDirs(t)
		h, _ := startHelper(t, state, evidence, surface, runName())
		h.ask(Request{Op: OpDo, Action: ptr(fileSpec("one", "1"))})
		_ = h.cmd.Process.Signal(syscall.SIGINT)
		_ = h.cmd.Process.Signal(syscall.SIGHUP)
		if r := h.ask(Request{Op: OpSnapshot, Name: "after-sigint"}); !r.OK {
			t.Fatalf("the helper after SIGINT and SIGHUP: %+v", r)
		}
		if !present(h.runDir(), "file-one") {
			t.Fatal("the signals undid the change")
		}
		end := h.ask(Request{Op: OpRestore})
		if end.Result == nil || end.Result.Verdict != Clean || present(h.runDir(), "file-one") {
			t.Fatalf("restore: %+v", end)
		}
	})
	t.Run("a left-over difference is reported", func(t *testing.T) {
		state, evidence, surface := newHelperDirs(t)
		h, _ := startHelper(t, state, evidence, surface, runName())
		writeFile(t, surface, "route a\nroute z\n")
		end := h.ask(Request{Op: OpRestore})
		if end.Result == nil || end.Result.Verdict != Left || end.Result.Left[0].Extra[0] != "route z" {
			t.Fatalf("restore: %+v", end.Result)
		}
		if _, err := os.Stat(filepath.Join(evidence, "snapshots", "99-after-restore", "test-file.out")); err != nil {
			t.Errorf("the raw snapshot: %v", err)
		}
	})
}

func ptr[T any](v T) *T { return &v }

// assertClosed: the run is finished: journal closed, no active run, the
// dead-man disarmed and gone, the result and journal in the evidence.
func assertClosed(t *testing.T, h *helperRun) {
	t.Helper()
	dir := h.runDir()
	eventually(t, 15*time.Second, "the run closed", func() bool {
		active, err := StateConfig{Dir: h.state, AllowNonRoot: true}.Active()
		return err == nil && active == ""
	})
	j, err := OpenJournal(dir, "")
	if err != nil || !j.Closed() || len(j.Pending()) != 0 {
		t.Errorf("journal: closed %v pending %v %v", j != nil && j.Closed(), j, err)
	}
	if !present(dir, stopFile) {
		t.Error("no stop file for the dead-man")
	}
	eventually(t, 5*time.Second, "the dead-man exited", func() bool { return armed(dir) != nil })
	for _, glob := range []string{"restore/result-*.json", "journal/journal-*.jsonl", "snapshots/00-baseline/test-file.out"} {
		if m, _ := filepath.Glob(filepath.Join(h.evidence, glob)); len(m) != 1 {
			t.Errorf("evidence %s: %v", glob, m)
		}
	}
}

func TestTheDeadmanRestoresAKilledHelper(t *testing.T) {
	state, evidence, surface := newHelperDirs(t)
	h, _ := startHelper(t, state, evidence, surface, runName())
	if r := h.ask(Request{Op: OpDo, Action: ptr(fileSpec("one", "1"))}); !r.OK {
		t.Fatalf("do: %+v", r)
	}
	if err := h.cmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, h)
	dir := h.runDir()
	if present(dir, "file-one") {
		t.Error("the change outlived the helper")
	}
	b, err := trusteddir.ReadFile(dir, resultFile)
	var res Result
	if err == nil {
		err = json.Unmarshal(b, &res)
	}
	if err != nil || res.Verdict != Clean || !strings.Contains(res.By, "dead-man") || !strings.Contains(res.By, "helper is gone") {
		t.Errorf("result: %+v %v", res, err)
	}
}

func TestAnUnfinishedRunBlocksTheNextUntilRestored(t *testing.T) {
	state, evidence, surface := newHelperDirs(t)
	first := runName()
	h, _ := startHelper(t, state, evidence, surface, first)
	h.ask(Request{Op: OpDo, Action: ptr(fileSpec("one", "1"))})
	// Everything killed: the dead-man first, then the helper.
	killDeadman(state, first)
	_ = h.cmd.Process.Signal(syscall.SIGKILL)
	_ = h.cmd.Wait()

	if _, hello := startHelper(t, state, evidence, surface, runName()); hello.OK || !strings.Contains(hello.Err, "devicetest restore") {
		t.Fatalf("a new run while one is unfinished: %+v", hello)
	}
	cmd := childCommand(t, []string{stateEnv + "=" + state, surfaceEnv + "=" + surface, nonRootEnv + "=1"}, "restore")
	out, err := cmd.Output()
	var resp Response
	if err == nil {
		err = json.Unmarshal(out, &resp)
	}
	if err != nil || !resp.OK || resp.Result.Verdict != Clean || present(h.runDir(), "file-one") {
		t.Fatalf("restore: %s %v", out, err)
	}
	if _, hello := startHelper(t, state, evidence, surface, runName()); !hello.OK {
		t.Errorf("a new run after the restore: %+v", hello)
	}
}
