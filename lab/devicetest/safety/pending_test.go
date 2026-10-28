//go:build darwin || linux

package safety

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/trusteddir"
)

// pendingFixture is a run pending a restore, built in the test's own
// directories: its record, baseline, journal and left pointer, as a run
// killed in the boot it records leaves them.
type pendingFixture struct {
	t        *testing.T
	cfg      stateConfig
	state    string
	evidence string
	run      string
	h        *host
	j        *journal
}

// thisBoot is the boot session the test runs in.
func thisBoot(t *testing.T) string {
	t.Helper()
	b, err := trusteddir.BootSession()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func newPendingRun(t *testing.T, sfs []surface, exec runner, boot string) *pendingFixture {
	t.Helper()
	base := tempDir(t)
	f := &pendingFixture{t: t, state: filepath.Join(base, "state"), evidence: filepath.Join(base, "evidence"), run: runName()}
	f.cfg = stateConfig{dir: f.state, allowNonRoot: true, surfaces: sfs, exec: exec}
	if err := os.Mkdir(f.evidence, 0o700); err != nil {
		t.Fatal(err)
	}
	state := openDir(t, f.state)
	runDir := openDir(t, filepath.Join(f.state, "run-"+f.run))
	info := runInfo{Run: f.run, Evidence: f.evidence, UID: os.Getuid(), GID: os.Getgid(), Boot: boot}
	if err := trusteddir.WriteFile(runDir, runInfoFile, mustJSON(info)); err != nil {
		t.Fatal(err)
	}
	ev, err := openEvidence(f.evidence, os.Getuid(), os.Getgid())
	if err != nil {
		t.Fatal(err)
	}
	f.h = &host{runDir: runDir, boot: boot, runBoot: boot, surfaces: sfs, exec: exec, evidence: ev}
	if f.h.baseline, err = f.h.snapshot(t.Context(), baselineName); err != nil {
		t.Fatal(err)
	}
	if f.j, err = createJournal(runDir, f.run, boot); err != nil {
		t.Fatal(err)
	}
	if err := trusteddir.WriteFile(state, leftFile, []byte(f.run+"\n")); err != nil {
		t.Fatal(err)
	}
	return f
}

// do makes a change through the journal, as the run did.
func (f *pendingFixture) do(spec Spec) {
	f.t.Helper()
	if _, err := (&engine{h: f.h, j: f.j, armed: isArmed}).do(f.t.Context(), spec); err != nil {
		f.t.Fatal(err)
	}
}

// killed leaves the journal as a killed helper does: open for a restore.
func (f *pendingFixture) killed() { _ = f.j.release() }

func (f *pendingFixture) restore() (Result, error) {
	return restoreRun(f.t.Context(), f.cfg, "test", "")
}

func (f *pendingFixture) pointer(name string) string {
	return pendingFile(testDirs{state: f.state}, name)
}

func (f *pendingFixture) runFile(name string) string {
	b, _ := os.ReadFile(filepath.Join(f.state, "run-"+f.run, name))
	return string(b)
}

func (f *pendingFixture) evidenceResults() []string {
	m, _ := filepath.Glob(filepath.Join(f.evidence, "restore", "result-*.json"))
	return m
}

func TestAPendingRunIsLeftInItsOwnBootAndResetByALaterOne(t *testing.T) {
	for _, tc := range []struct {
		name, boot, want string
		cleared          bool
	}{
		{"the run's own boot", "", Left, false},
		{"a later boot", "an-earlier-boot", ResetByReboot, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			surface := filepath.Join(tempDir(t), "surface.txt")
			writeFile(t, surface, "route a\n")
			boot := tc.boot
			if boot == "" {
				boot = thisBoot(t)
			}
			f := newPendingRun(t, testSurfaces(surface), nil, boot)
			f.do(fileSpec("one", "1"))
			f.killed()
			writeFile(t, surface, "route a\nroute z\n") // not the run's: still differs after its undo
			res, err := f.restore()
			if err != nil || res.Verdict != tc.want || present(f.h.runDir, "file-one") {
				t.Fatalf("restore: %+v %v", res, err)
			}
			if cleared := f.pointer(leftFile) == ""; cleared != tc.cleared {
				t.Errorf("left %q", f.pointer(leftFile))
			}
			if !strings.Contains(f.runFile(resultFile), tc.want) || len(f.evidenceResults()) != 1 {
				t.Errorf("the result isn't in the run directory and the evidence: %s %v", f.runFile(resultFile), f.evidenceResults())
			}
		})
	}
}

func TestARunThatCantBeRestoredIsForgottenOnlyInALaterBoot(t *testing.T) {
	for _, tc := range []struct {
		name    string
		corrupt bool
		gone    bool
	}{{"a change that can't be undone", false, false}, {"a journal that doesn't read back", true, false}, {"a journal that's gone", true, true}} {
		t.Run(tc.name, func(t *testing.T) {
			surface := filepath.Join(tempDir(t), "surface.txt")
			writeFile(t, surface, "route a\n")
			for _, boot := range []string{thisBoot(t), "an-earlier-boot"} {
				f := newPendingRun(t, testSurfaces(surface), nil, boot)
				f.do(fileSpec("one", "1"))
				writeFile(t, filepath.Join(f.state, "run-"+f.run, "file-one"), "someone else's") // the undo refuses it
				if tc.corrupt {
					_, _ = f.j.f.WriteString("{\"seq\":9,\"sta\n")
				}
				f.killed()
				if tc.gone {
					if err := os.Remove(filepath.Join(f.state, "run-"+f.run, journalName)); err != nil {
						t.Fatal(err)
					}
				}
				// A restore that fails still names its run, for -forget.
				if res, err := f.restore(); tc.corrupt != (err != nil) || err == nil && res.Verdict != Left || res.Run != f.run {
					t.Fatalf("restore: %+v %v", res, err)
				}
				if f.pointer(leftFile) != f.run {
					t.Fatalf("not pending: left %q", f.pointer(leftFile))
				}
				// Another run, of a later boot too, isn't the pending one.
				other := openDir(t, filepath.Join(f.state, "run-other"))
				if err := trusteddir.WriteFile(other, runInfoFile, mustJSON(runInfo{Run: "other", Boot: "an-earlier-boot"})); err != nil {
					t.Fatal(err)
				}
				if oj, err := createJournal(other, "other", "an-earlier-boot"); err != nil {
					t.Fatal(err)
				} else {
					_ = oj.release()
				}
				if _, err := forgetRun(t.Context(), f.cfg, "other", "test"); err == nil || f.pointer(leftFile) != f.run {
					t.Errorf("another run's name forgot this one: %v", err)
				}
				res, err := forgetRun(t.Context(), f.cfg, f.run, "test")
				if boot == thisBoot(t) {
					if err == nil || !strings.Contains(err.Error(), "this boot") || f.pointer(leftFile) != f.run {
						t.Errorf("forgotten in its own boot: %+v %v", res, err)
					}
					continue
				}
				if err != nil || res.Verdict != Forgotten || f.pointer(leftFile) != "" || f.pointer(activeFile) != "" {
					t.Fatalf("forget in a later boot: %+v %v, left %q", res, err, f.pointer(leftFile))
				}
				// The journal read back: the restore's undos ran first, and
				// the one that can't be undone is what was forgotten.
				if !tc.corrupt && (len(res.Failed) != 1 || !strings.Contains(res.Failed[0], "holds something else")) {
					t.Errorf("the undos before forgetting: %+v", res.Failed)
				}
				says := strings.Join(res.Notes, "\n")
				if !tc.gone && (!strings.Contains(says, "journal: change 1") || tc.corrupt != strings.Contains(says, "doesn't read")) {
					t.Errorf("what the journal still says:\n%s", says)
				}
				if !strings.Contains(f.runFile(resultFile), Forgotten) || len(f.evidenceResults()) == 0 {
					t.Errorf("the result isn't kept: %s %v", f.runFile(resultFile), f.evidenceResults())
				}
				if !tc.corrupt {
					if j, err := openJournal(f.h.runDir, ""); err != nil || !j.done {
						t.Errorf("the journal isn't closed: %v", err)
					}
				}
			}
		})
	}
}

func TestARunStaysActiveWhenItsLeftPointerCantBeWritten(t *testing.T) {
	surface := filepath.Join(tempDir(t), "surface.txt")
	writeFile(t, surface, "route a\n")
	f := newPendingRun(t, testSurfaces(surface), nil, thisBoot(t))
	f.do(fileSpec("one", "1"))
	f.killed()
	state := openDir(t, f.state)
	// Killed mid-run: active names it, left doesn't exist yet.
	if err := errors.Join(trusteddir.Remove(state, leftFile), trusteddir.WriteFile(state, activeFile, []byte(f.run+"\n"))); err != nil {
		t.Fatal(err)
	}
	writeFile(t, surface, "route a\nroute z\n")
	if err := os.Mkdir(filepath.Join(f.state, leftFile+".tmp"), 0o700); err != nil { // trusteddir.WriteFile's temporary
		t.Fatal(err)
	}
	res, err := f.restore()
	if err == nil || res.Verdict != Left || f.pointer(activeFile) != f.run || f.pointer(leftFile) != "" {
		t.Fatalf("left unwritable: %+v %v, active %q", res, err, f.pointer(activeFile))
	}
	if err := os.Remove(filepath.Join(f.state, leftFile+".tmp")); err != nil {
		t.Fatal(err)
	}
	if res, err := f.restore(); err != nil || res.Verdict != Left || f.pointer(leftFile) != f.run || f.pointer(activeFile) != "" {
		t.Errorf("left writable again: %+v %v", res, err)
	}
}

func TestARestoreWithoutItsEvidenceFolderSaysSo(t *testing.T) {
	surface := filepath.Join(tempDir(t), "surface.txt")
	writeFile(t, surface, "route a\n")
	f := newPendingRun(t, testSurfaces(surface), nil, thisBoot(t))
	f.killed()
	if err := os.RemoveAll(f.evidence); err != nil {
		t.Fatal(err)
	}
	res, err := f.restore()
	if err != nil || !strings.Contains(strings.Join(res.Notes, "\n"), "won't open") || !strings.Contains(f.runFile(resultFile), "won't open") {
		t.Errorf("restore: %+v %v", res, err)
	}
}

func TestADeadmanRestoresOnlyItsOwnRun(t *testing.T) {
	surface := filepath.Join(tempDir(t), "surface.txt")
	writeFile(t, surface, "route a\n")
	f := newPendingRun(t, testSurfaces(surface), nil, thisBoot(t))
	f.do(fileSpec("one", "1"))
	f.killed()
	res, err := restoreRun(t.Context(), f.cfg, "the dead-man of another run", "another-run")
	if err != nil || res.Verdict != Nothing || f.pointer(leftFile) != f.run || !present(f.h.runDir, "file-one") {
		t.Errorf("another run's dead-man: %+v %v", res, err)
	}
}

func TestABaselineThatCantReadASurfaceStopsTheRun(t *testing.T) {
	d := newHelperDirs(t)
	if err := os.Remove(d.surface); err != nil { // cat fails: the surface can't be read
		t.Fatal(err)
	}
	run := runName()
	_, hello := startHelper(t, d, run)
	if hello.OK || !strings.Contains(hello.Err, "can't read test-file") || !strings.Contains(hello.Err, "stderr") {
		t.Fatalf("a run started on an unreadable baseline: %+v", hello)
	}
	var res Result
	b, err := os.ReadFile(filepath.Join(d.state, "run-"+run, resultFile))
	if err == nil {
		err = json.Unmarshal(b, &res)
	}
	if err != nil || res.Verdict != Nothing || !strings.Contains(strings.Join(res.Notes, " "), "didn't start") {
		t.Errorf("the didn't-start result: %+v %v", res, err)
	}
	if pendingFile(d, activeFile) != "" || pendingFile(d, leftFile) != "" {
		t.Error("a run that didn't start is pending")
	}
}

// Outside the helper that started it, a capture whose pid never reached
// the journal can't be shown gone: LEFT, until the reboot that ends it.
func TestACaptureWithNoJournaledPidIsLeftUntilAReboot(t *testing.T) {
	for _, tc := range []struct {
		boot, want string
	}{{"boot-a", Left}, {"boot-b", Clean}} {
		dir := openDir(t, filepath.Join(tempDir(t), "run"))
		j, err := createJournal(dir, "r", "boot-a")
		if err != nil {
			t.Fatal(err)
		}
		capture := &captureAction{Iface: "en9"}
		if _, err := j.intent(capture, mustJSON(capture)); err != nil {
			t.Fatal(err)
		}
		_ = j.release()
		if j, err = openJournal(dir, tc.boot); err != nil {
			t.Fatal(err)
		}
		res := (&engine{h: noSurfaces(dir, tc.boot), j: j, armed: refuseChanges}).restore(t.Context(), "test")
		if res.Verdict != tc.want || (tc.want == Left) != (len(j.pending()) == 1) {
			t.Errorf("restored in %s: %+v", tc.boot, res)
		}
	}
}

func TestNoBaselineAndNoChangeIsNothingToRestore(t *testing.T) {
	dir := openDir(t, filepath.Join(tempDir(t), "run"))
	j, err := createJournal(dir, "r", "boot-a")
	if err != nil {
		t.Fatal(err)
	}
	res := (&engine{h: &host{runDir: dir, boot: "boot-a", surfaces: []surface{}}, j: j, armed: refuseChanges}).restore(t.Context(), "test")
	if res.Verdict != Nothing {
		t.Errorf("%+v", res)
	}
}

// Each surface a snapshot reads is progress for the dead-man: a slow one
// can't make a healthy restore look hung.
func TestASnapshotBeatsAfterEachSurface(t *testing.T) {
	dir := tempDir(t)
	var sfs []surface
	for _, n := range []string{"a", "b", "c"} {
		writeFile(t, filepath.Join(dir, n), n+"\n")
		sfs = append(sfs, surface{name: n, argv: []string{"/bin/cat", filepath.Join(dir, n)}, norm: catLines})
	}
	h := &host{runDir: openDir(t, filepath.Join(dir, "run")), surfaces: sfs}
	if _, err := h.snapshot(t.Context(), afterName); err != nil {
		t.Fatal(err)
	}
	if h.beats != len(sfs) {
		t.Errorf("%d beats for %d surfaces", h.beats, len(sfs))
	}
}

// One root entry point, and an answer already sent over the protocol
// isn't printed again.
func TestTheRootSidePrintsAnErrorOnce(t *testing.T) {
	var out, log strings.Builder
	state := stateConfig{dir: filepath.Join(tempDir(t), "state"), allowNonRoot: true}
	if code := rootMain(t.Context(), []string{"helper", "-run", "x"}, state, strings.NewReader(""), &out, &log); code != 1 {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(out.String(), `"err":"helper: -run`) || log.Len() != 0 {
		t.Errorf("answered %q, printed %q", out.String(), log.String())
	}
	out.Reset()
	if code := rootMain(t.Context(), []string{"no-such-mode"}, state, nil, &out, &log); code != 1 || !strings.Contains(log.String(), "no mode") {
		t.Errorf("an unknown mode: exit %d, printed %q", code, log.String())
	}
}

// A baseline on disk that doesn't read back says so, and what to do: it
// was taken, so "no baseline was taken" would be untrue.
func TestABaselineThatDoesntReadBackSaysRebootThenRestore(t *testing.T) {
	surface := filepath.Join(tempDir(t), "surface.txt")
	writeFile(t, surface, "route a\n")
	f := newPendingRun(t, testSurfaces(surface), nil, thisBoot(t))
	f.do(fileSpec("one", "1"))
	f.killed()
	writeFile(t, filepath.Join(f.state, "run-"+f.run, snapshotFile(baselineName)), "{cut")
	res, err := f.restore()
	if err != nil || res.Verdict != Left || !strings.Contains(strings.Join(res.Failed, " "), "can't be read back") ||
		!strings.Contains(strings.Join(res.Failed, " "), "reboot, then run devicetest restore") {
		t.Errorf("restore: %+v %v", res, err)
	}
}

// A helper killed while it took the baseline leaves a cut one and no
// change: nothing to compare, NOTHING-TO-RESTORE, the run closed.
func TestACutBaselineWithNoChangeIsNothingToRestore(t *testing.T) {
	surface := filepath.Join(tempDir(t), "surface.txt")
	writeFile(t, surface, "route a\n")
	f := newPendingRun(t, testSurfaces(surface), nil, thisBoot(t))
	f.killed()
	writeFile(t, filepath.Join(f.state, "run-"+f.run, snapshotFile(baselineName)), "")
	if res, err := f.restore(); err != nil || res.Verdict != Nothing || f.pointer(leftFile) != "" {
		t.Errorf("restore: %+v %v", res, err)
	}
}

// A run record that names no boot is never taken for another boot's.
func TestARunRecordWithNoBootIsRefused(t *testing.T) {
	surface := filepath.Join(tempDir(t), "surface.txt")
	writeFile(t, surface, "route a\n")
	f := newPendingRun(t, testSurfaces(surface), nil, thisBoot(t))
	f.killed()
	if err := trusteddir.WriteFile(f.h.runDir, runInfoFile, mustJSON(runInfo{Run: f.run, Evidence: f.evidence})); err != nil {
		t.Fatal(err)
	}
	for name, do := range map[string]func() (Result, error){
		"restore": f.restore,
		"forget":  func() (Result, error) { return forgetRun(t.Context(), f.cfg, f.run, "test") },
	} {
		if res, err := do(); err == nil || !strings.Contains(err.Error(), "no boot") || f.pointer(leftFile) != f.run {
			t.Errorf("%s: %+v %v", name, res, err)
		}
	}
}

// Only a compared surface unreadable at the baseline stops a run; one
// that is information only (pfctl may lack the listing) never does.
func TestOnlyAComparedSurfaceUnreadableAtTheBaselineStopsARun(t *testing.T) {
	sfs := []surface{
		{name: "compared", norm: catLines},
		{name: "info", norm: catLines, info: true},
		{name: "recorded"},
	}
	for _, tc := range []struct {
		unreadable string
		refused    bool
	}{{"compared", true}, {"info", false}, {"recorded", false}} {
		base := &snapshot{Name: baselineName, Lines: map[string][]string{}, Unreadable: map[string]string{tc.unreadable: "exit 1"}}
		if err := unreadableCompared(sfs, base); (err != nil) != tc.refused {
			t.Errorf("%s unreadable: %v", tc.unreadable, err)
		}
	}
}

// A run killed before its first change, whose baseline couldn't read a
// compared surface, has nothing to compare: NOTHING-TO-RESTORE.
func TestABaselineWithAnUnreadableSurfaceAndNoChangeIsNothingToRestore(t *testing.T) {
	missing := filepath.Join(tempDir(t), "missing.txt")
	f := newPendingRun(t, testSurfaces(missing), nil, thisBoot(t))
	f.killed()
	if res, err := f.restore(); err != nil || res.Verdict != Nothing || f.pointer(leftFile) != "" {
		t.Errorf("restore: %+v %v", res, err)
	}
}

// root-restore whose reader is gone (a closed terminal took the user side)
// isn't killed by SIGPIPE: it ends with a status of its own, after its
// root copy's removal.
func TestRootRestoreOutlivesAGoneReader(t *testing.T) {
	d := newHelperDirs(t)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	_ = r.Close()
	cmd := childCommand(t, d.env(), "root-restore")
	cmd.Stdout = w
	err = cmd.Run()
	_ = w.Close()
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			t.Fatalf("root-restore died of %v", ws.Signal())
		}
	}
}
