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

type watched struct {
	fire bool
	why  string
	took time.Duration
}

// startWatch runs watch on dir, bounded at 10 s so a broken dead-man
// fails the test instead of hanging it.
func startWatch(t *testing.T, dir *os.File, cfg deadmanConfig) <-chan watched {
	out := make(chan watched, 1)
	start := time.Now()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	go func() {
		defer cancel()
		fire, why := watch(ctx, dir, cfg)
		if ctx.Err() != nil {
			why = "still watching after 10 s"
		}
		out <- watched{fire, why, time.Since(start)}
	}()
	return out
}

func beat(dir *os.File, every, until time.Duration) {
	n, stop := 0, time.Now().Add(until)
	for time.Now().Before(stop) {
		n++
		_ = trusteddir.WriteFile(dir, heartbeatFile, []byte(strconv.Itoa(n)))
		time.Sleep(every)
	}
}

func TestTheDeadmanFiresWhenItMustAndOnlyThen(t *testing.T) {
	fast := func(t *testing.T) deadmanConfig {
		helper, start := startSleep(t)
		return deadmanConfig{helperPID: helper.Process.Pid, helperStart: start, deadline: time.Hour, poll: 20 * time.Millisecond}
	}
	t.Run("the helper killed", func(t *testing.T) {
		cfg := fast(t)
		got := startWatch(t, openDir(t, tempDir(t)), cfg)
		_ = syscall.Kill(cfg.helperPID, syscall.SIGKILL)
		if w := <-got; !w.fire || !strings.Contains(w.why, "helper is gone") {
			t.Errorf("%+v", w)
		}
	})
	t.Run("another process with the helper's pid", func(t *testing.T) {
		cfg := fast(t)
		cfg.helperStart++
		if w := <-startWatch(t, openDir(t, tempDir(t)), cfg); !w.fire || !strings.Contains(w.why, "helper is gone") {
			t.Errorf("%+v", w)
		}
	})
	t.Run("the stop file", func(t *testing.T) {
		dir := openDir(t, tempDir(t))
		got := startWatch(t, dir, fast(t))
		if err := trusteddir.WriteFile(dir, stopFile, nil); err != nil {
			t.Fatal(err)
		}
		if w := <-got; w.fire {
			t.Errorf("fired: %+v", w)
		}
	})
	t.Run("a directory it can't read never disarms it", func(t *testing.T) {
		cfg := fast(t)
		dir, err := trusteddir.Make(tempDir(t))
		if err != nil {
			t.Fatal(err)
		}
		_ = dir.Close() // every look at it fails (EBADF): none is a stop file
		got := startWatch(t, dir, cfg)
		_ = syscall.Kill(cfg.helperPID, syscall.SIGKILL)
		if w := <-got; !w.fire {
			t.Errorf("disarmed by an error: %+v", w)
		}
	})
	t.Run("the deadline without a restore", func(t *testing.T) {
		cfg := fast(t)
		cfg.deadline = 300 * time.Millisecond
		if w := <-startWatch(t, openDir(t, tempDir(t)), cfg); !w.fire || !strings.Contains(w.why, "deadline") || w.took < cfg.deadline {
			t.Errorf("%+v", w)
		}
	})
	t.Run("a fresh heartbeat holds it until the limit", func(t *testing.T) {
		dir := openDir(t, tempDir(t))
		cfg := fast(t)
		cfg.deadline, cfg.limit, cfg.stale = 100*time.Millisecond, 1200*time.Millisecond, 300*time.Millisecond
		got := startWatch(t, dir, cfg)
		go beat(dir, 30*time.Millisecond, 5*time.Second)
		if w := <-got; !w.fire || !strings.Contains(w.why, "limit") || w.took < cfg.limit {
			t.Errorf("%+v", w)
		}
	})
	t.Run("a heartbeat that goes stale", func(t *testing.T) {
		dir := openDir(t, tempDir(t))
		cfg := fast(t)
		cfg.deadline, cfg.stale = 100*time.Millisecond, 300*time.Millisecond
		got := startWatch(t, dir, cfg)
		beat(dir, 30*time.Millisecond, 600*time.Millisecond)
		if w := <-got; !w.fire || !strings.Contains(w.why, "deadline") || w.took < 600*time.Millisecond {
			t.Errorf("%+v", w)
		}
	})
}

// A Mac's monotonic clock stops while it sleeps; the wall clock doesn't.
func TestTheBudgetCountsTheLargerOfBothClocks(t *testing.T) {
	now := time.Now()
	if got := elapsedSince(now, now.Round(0).Add(-time.Hour), now); got < time.Hour {
		t.Errorf("an hour of wall-clock time asleep counted as %v", got)
	}
	if got := elapsedSince(now.Add(-time.Minute), now.Round(0).Add(time.Hour), now); got < time.Minute {
		t.Errorf("the wall clock set back counted as %v", got)
	}
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

func (d testDirs) env() []string {
	return []string{stateEnv + "=" + d.state, surfaceEnv + "=" + d.surface, nonRootEnv + "=1"}
}

func startHelper(t *testing.T, d testDirs, run string) (*helperRun, Response) {
	t.Helper()
	cmd := childCommand(t, d.env(), "helper", "-run", run, "-evidence", d.evidence,
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
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); killDeadman(d.state, run) })
	h := &helperRun{t: t, cmd: cmd, in: in, out: bufio.NewScanner(stdout), state: d.state, evidence: d.evidence, surface: d.surface, run: run}
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

func (h *helperRun) do(spec Spec) {
	h.t.Helper()
	if r := h.ask(Request{Op: OpDo, Change: &spec}); !r.OK {
		h.t.Fatalf("do: %+v", r)
	}
}

// killDeadman stops a test's dead-man, if it still runs.
func killDeadman(state, run string) {
	b, err := os.ReadFile(filepath.Join(state, "run-"+run, armedFile))
	if err != nil {
		return
	}
	var pid int
	var start int64
	if _, err := fmt.Sscan(string(b), &pid, &start); err == nil && running(pid, start) {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
}

type testDirs struct{ state, evidence, surface string }

func newHelperDirs(t *testing.T) testDirs {
	t.Helper()
	base := tempDir(t)
	d := testDirs{state: filepath.Join(base, "state"), evidence: filepath.Join(base, "evidence"), surface: filepath.Join(base, "surface.txt")}
	writeFile(t, d.surface, "route a\n")
	if err := os.Mkdir(d.evidence, 0o700); err != nil {
		t.Fatal(err)
	}
	return d
}

var runs atomic.Int32

func runName() string { return fmt.Sprintf("test-%02d", runs.Add(1)) }

// restoreChild runs `devicetest restore`'s root mode as a child.
func restoreChild(t *testing.T, d testDirs, args ...string) (Response, error) {
	t.Helper()
	out, err := childCommand(t, d.env(), "restore", args...).Output()
	var resp Response
	if jerr := json.Unmarshal(out, &resp); jerr != nil {
		t.Fatalf("restore printed %q: %v (%v)", out, jerr, err)
	}
	return resp, err
}

func pendingFile(d testDirs, name string) string {
	b, _ := os.ReadFile(filepath.Join(d.state, name))
	return strings.TrimSpace(string(b))
}

func TestTheHelperRestores(t *testing.T) {
	t.Run("when its input ends", func(t *testing.T) {
		d := newHelperDirs(t)
		h, hello := startHelper(t, d, runName())
		if !hello.OK {
			t.Fatalf("start: %+v", hello)
		}
		h.do(fileSpec("one", "1"))
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
	t.Run("after SIGINT and SIGHUP, only when asked", func(t *testing.T) {
		d := newHelperDirs(t)
		h, _ := startHelper(t, d, runName())
		h.do(fileSpec("one", "1"))
		_ = h.cmd.Process.Signal(syscall.SIGINT)
		_ = h.cmd.Process.Signal(syscall.SIGHUP)
		h.do(fileSpec("two", "2"))
		if !present(h.runDir(), "file-one") {
			t.Fatal("the signals undid the change")
		}
		end := h.ask(Request{Op: OpRestore})
		if end.Result == nil || end.Result.Verdict != Clean || present(h.runDir(), "file-one") || present(h.runDir(), "file-two") {
			t.Fatalf("restore: %+v", end)
		}
	})
	t.Run("no operation outside the protocol", func(t *testing.T) {
		d := newHelperDirs(t)
		h, _ := startHelper(t, d, runName())
		if r := h.ask(Request{Op: "snapshot", Name: baselineName}); r.OK || !strings.Contains(r.Err, "no operation") {
			t.Errorf("a snapshot asked for: %+v", r)
		}
	})
}

// assertClosed: the run is finished clean: journal closed, nothing
// pending, the dead-man disarmed and gone, the result and journal in the
// evidence.
func assertClosed(t *testing.T, h *helperRun) {
	t.Helper()
	d := testDirs{state: h.state}
	eventually(t, 15*time.Second, "the run closed", func() bool {
		return pendingFile(d, activeFile) == "" && pendingFile(d, leftFile) == ""
	})
	dir := h.runDir()
	if j, err := openJournal(dir, ""); err != nil || !j.closed() || len(j.pending()) != 0 {
		t.Errorf("journal: %v", err)
	}
	if !present(dir, stopFile) {
		t.Error("no stop file for the dead-man")
	}
	eventually(t, 5*time.Second, "the dead-man exited", func() bool { return armed(dir) != nil })
	for _, glob := range []string{"restore/result-*.json", "journal/journal-*.jsonl", "snapshots/" + baselineName + "/test-file.out"} {
		if m, _ := filepath.Glob(filepath.Join(h.evidence, glob)); len(m) != 1 {
			t.Errorf("evidence %s: %v", glob, m)
		}
	}
}

func TestTheDeadmanRestoresAKilledHelper(t *testing.T) {
	d := newHelperDirs(t)
	h, _ := startHelper(t, d, runName())
	h.do(fileSpec("one", "1"))
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

func TestAPendingRunBlocksTheNextUntilRestoredClean(t *testing.T) {
	d := newHelperDirs(t)
	first := runName()
	h, _ := startHelper(t, d, first)
	h.do(fileSpec("one", "1"))
	// Everything killed: the dead-man first, then the helper.
	killDeadman(d.state, first)
	_ = h.cmd.Process.Signal(syscall.SIGKILL)
	_ = h.cmd.Wait()
	if _, hello := startHelper(t, d, runName()); hello.OK || !strings.Contains(hello.Err, "devicetest restore") {
		t.Fatalf("a new run while one is unfinished: %+v", hello)
	}

	// The restore finds the host changed: LEFT, and the run stays pending.
	writeFile(t, d.surface, "route a\nroute z\n")
	resp, err := restoreChild(t, d)
	if err != nil || resp.Result.Verdict != Left || present(h.runDir(), "file-one") {
		t.Fatalf("restore with the host changed: %+v %v", resp, err)
	}
	if pendingFile(d, leftFile) != first || pendingFile(d, activeFile) != "" {
		t.Fatalf("left %q active %q", pendingFile(d, leftFile), pendingFile(d, activeFile))
	}
	if _, hello := startHelper(t, d, runName()); hello.OK {
		t.Fatal("a new run while one is left not clean")
	}

	// Put back by hand: the next restore compares again and clears it.
	writeFile(t, d.surface, "route a\n")
	resp, err = restoreChild(t, d)
	if err != nil || resp.Result.Verdict != Clean || resp.Result.Run != first || pendingFile(d, leftFile) != "" {
		t.Fatalf("restore after the fix: %+v %v", *resp.Result, err)
	}
	if m, _ := filepath.Glob(filepath.Join(d.state, "run-"+first, "snapshot-"+afterName+"-*.json")); len(m) != 1 {
		t.Errorf("the second restore's snapshot under its own name: %v", m)
	}
	if resp, err := restoreChild(t, d); err != nil || resp.Result.Verdict != Nothing {
		t.Errorf("a restore with nothing pending: %+v %v", resp, err)
	}
	if _, hello := startHelper(t, d, runName()); !hello.OK {
		t.Errorf("a new run after the clean restore: %+v", hello)
	}
}

func TestAnUnreadablePendingPointerIsAnError(t *testing.T) {
	d := newHelperDirs(t)
	if err := os.MkdirAll(filepath.Join(d.state, leftFile), 0o700); err != nil {
		t.Fatal(err)
	}
	if resp, err := restoreChild(t, d); err == nil || resp.OK || resp.Result.Verdict == Clean || resp.Result.Verdict == Nothing {
		t.Errorf("a pointer that isn't a file: %+v %v", resp, err)
	}
}

func TestARestoreAfterARebootFindsTheRootCopyGone(t *testing.T) {
	d := newHelperDirs(t)
	run := runName()
	h, _ := startHelper(t, d, run)
	h.do(fileSpec("one", "1"))
	killDeadman(d.state, run)
	_ = h.cmd.Process.Signal(syscall.SIGKILL)
	_ = h.cmd.Wait()
	// The run's record names a root copy the reboot emptied away.
	info := filepath.Join(d.state, "run-"+run, runInfoFile)
	b, _ := os.ReadFile(info)
	var ri runInfo
	_ = json.Unmarshal(b, &ri)
	ri.RootCopy = rootCopyBase + "/tpdt.GoneGone"
	writeFile(t, info, string(mustJSON(ri)))
	if resp, err := restoreChild(t, d); err != nil || !resp.OK || resp.Result.Verdict != Clean {
		t.Errorf("restore: %+v %v", resp, err)
	}
}

func TestOldRunsArePrunedPendingOnesNever(t *testing.T) {
	state := openDir(t, tempDir(t))
	mk := func(name string) {
		p := filepath.Join(state.Name(), name)
		if err := os.Mkdir(p, 0o700); err != nil {
			t.Fatal(err)
		}
		writeFile(t, filepath.Join(p, journalName), "{}\n")
	}
	for i := range 12 {
		mk(fmt.Sprintf("run-202610%02dT000000Z-tp-096", i+1))
	}
	pending := "20261001T000000Z-tp-096"
	odd := filepath.Join(state.Name(), "run-20261002T000000Z-tp-096")
	if err := os.Symlink("/etc/hosts", filepath.Join(odd, "link")); err != nil {
		t.Fatal(err)
	}
	err := prune(state, pending)
	if err == nil || !strings.Contains(err.Error(), "isn't a regular file") {
		t.Errorf("a run directory holding a symlink: %v", err)
	}
	m, _ := filepath.Glob(filepath.Join(state.Name(), "run-*"))
	// 12 runs: the pending one and the one holding a symlink stay, and of
	// the other 10 the newest 9 make room for the run starting.
	if len(m) != 11 || !present(state, "run-"+pending) || !present(state, filepath.Base(odd)) || present(state, "run-20261003T000000Z-tp-096") {
		t.Errorf("after pruning: %v", m)
	}
	if _, err := os.Stat("/etc/hosts"); err != nil {
		t.Errorf("pruning followed the symlink: %v", err)
	}
}

func TestAStartingRunKeepsTheLastTen(t *testing.T) {
	d := newHelperDirs(t)
	if err := os.MkdirAll(d.state, 0o700); err != nil {
		t.Fatal(err)
	}
	for i := range 12 {
		if err := os.Mkdir(filepath.Join(d.state, fmt.Sprintf("run-old-%02d", i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	h, hello := startHelper(t, d, "zz-new")
	if !hello.OK {
		t.Fatalf("start: %+v", hello)
	}
	m, _ := filepath.Glob(filepath.Join(d.state, "run-*"))
	if len(m) != keepRuns || !present(openDir(t, d.state), "run-zz-new") {
		t.Errorf("run directories after a start: %v", m)
	}
	h.ask(Request{Op: OpRestore})
	if m, _ := filepath.Glob(filepath.Join(d.evidence, "*")); len(m) == 0 {
		t.Error("the evidence is gone")
	}
}
