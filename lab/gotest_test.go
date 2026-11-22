package lab

import (
	"context"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestTallyTestsCountsTopLevelResultsOnly(t *testing.T) {
	out := `=== RUN   TestA
=== RUN   TestA/sub
--- PASS: TestA (0.01s)
    --- PASS: TestA/sub (0.00s)
=== RUN   TestB
    prototype_test.go:120: in-node tests:
        --- PASS: TestRealityClientInterop (1.52s)
        --- SKIP: TestOther (0.00s)
--- SKIP: TestB (0.00s)
=== RUN   TestC
--- FAIL: TestC (0.00s)
    --- SKIP: TestC/sub (0.00s)
FAIL
`
	want := TestTally{Passed: 1, Failed: 1, Skipped: 1}
	if got := TallyTests([]byte(out)); got != want {
		t.Errorf("TallyTests = %+v, want %+v", got, want)
	}
}

func TestOnlySkippedCountsEveryRunOfAPackage(t *testing.T) {
	results := []GoTestResult{
		// In the node the interop test skips; the host's lab test runs it.
		{ImportPath: "x/reality", Tests: TestTally{Skipped: 1}},
		{ImportPath: "x/reality", Tests: TestTally{Passed: 1, Skipped: 1}},
		{ImportPath: "x/host-first", Tests: TestTally{Passed: 1}},
		{ImportPath: "x/host-first", Tests: TestTally{Skipped: 2}},
		{ImportPath: "x/skipped", Tests: TestTally{Skipped: 3}},
		{ImportPath: "x/failed", Failed: true, Tests: TestTally{Failed: 1, Skipped: 2}},
		{ImportPath: "x/none"}, // -run matched nothing here
		{ImportPath: "x/also-skipped", Tests: TestTally{Skipped: 1}},
	}
	want := []string{"x/also-skipped", "x/skipped"}
	if got := OnlySkipped(results); !slices.Equal(got, want) {
		t.Errorf("OnlySkipped = %q, want %q", got, want)
	}
}

// writeModule writes a module of files (slash-separated paths relative to
// its root) and returns its root.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	// go list reports directories with symlinks resolved (a temp dir may be
	// under one), and package dirs are taken relative to root.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files["go.mod"] = "module example.net/tagged\n\ngo 1.26\n"
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const (
	untaggedSkip = "package %s\n\nimport \"testing\"\n\nfunc TestNeedsSetUp(t *testing.T) { t.Skip(\"no set-up\") }\n"
	taggedPass   = "//go:build lab\n\npackage %s\n\nimport \"testing\"\n\nfunc TestSetsUp(t *testing.T) {}\n"
	taggedFail   = "//go:build lab\n\npackage %s\n\nimport \"testing\"\n\nfunc TestSetsUp(t *testing.T) { t.Fatal(\"broken\") }\n"
)

// needGoTool skips a test that runs the go command where it can't: under
// -short, and in a lab node, which has test binaries but no toolchain.
func needGoTool(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("runs the go command")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command here")
	}
}

// isolateGoEnv keeps the go command in a test's module from a workspace
// or module flags set around the test run.
func isolateGoEnv(t *testing.T) {
	t.Setenv("GOWORK", "off")
	t.Setenv("GOFLAGS", "-mod=mod")
}

func pkgFile(format, pkg string) string { return strings.Replace(format, "%s", pkg, 1) }

func TestListLabTaggedPackagesFindsPackagesWithLabTaggedTests(t *testing.T) {
	needGoTool(t)
	isolateGoEnv(t)
	root := writeModule(t, map[string]string{
		"plain/plain_test.go": pkgFile(untaggedSkip, "plain"),
		// One test file either way: the same count with and without the tag.
		"pair/pair_test.go":     "//go:build !lab\n\n" + pkgFile(untaggedSkip, "pair"),
		"pair/pair_lab_test.go": pkgFile(taggedPass, "pair"),
		"both/both_test.go":     pkgFile(untaggedSkip, "both"),
		"both/both_lab_test.go": pkgFile(taggedPass, "both"),
		"only/only_lab_test.go": pkgFile(taggedPass, "only"),
		"only/only.go":          "package only\n",
	})
	pkgs, err := ListLabTaggedPackages(t.Context(), root, "./...")
	if err != nil {
		t.Fatal(err)
	}
	want := []GoPackage{
		{ImportPath: "example.net/tagged/both", Dir: "both"},
		{ImportPath: "example.net/tagged/only", Dir: "only"},
		{ImportPath: "example.net/tagged/pair", Dir: "pair"},
	}
	if !slices.Equal(pkgs, want) {
		t.Errorf("ListLabTaggedPackages = %+v, want %+v", pkgs, want)
	}
}

func TestGoTestLabTaggedRunsTheTaggedTests(t *testing.T) {
	needGoTool(t)
	root := writeModule(t, map[string]string{
		"pass/pass_test.go":     pkgFile(untaggedSkip, "pass"),
		"pass/pass_lab_test.go": pkgFile(taggedPass, "pass"),
		"fail/fail_test.go":     pkgFile(untaggedSkip, "fail"),
		"fail/fail_lab_test.go": pkgFile(taggedFail, "fail"),
	})
	isolateGoEnv(t)

	var out syncBuffer
	res, err := GoTestLabTagged(t.Context(), root, GoPackage{ImportPath: "example.net/tagged/pass", Dir: "pass"}, &out, nil, "-test.v")
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if want := (TestTally{Passed: 1, Skipped: 1}); res.Tests != want || res.Failed {
		t.Errorf("pass: result %+v, want tests %+v, not failed\n%s", res, want, out.String())
	}

	out = syncBuffer{}
	res, err = GoTestLabTagged(t.Context(), root, GoPackage{ImportPath: "example.net/tagged/fail", Dir: "fail"}, &out, nil, "-test.v")
	if err == nil || !res.Failed || res.Tests.Failed != 1 {
		t.Errorf("fail: result %+v, err %v; want a failure\n%s", res, err, out.String())
	}
}

// TestLabPhases: a package's time in a node splits into its queue for
// the run's lab, its slot wait, the rest of its lab's start, its tests and
// its tear-down, which add up to the whole; a start that failed has no
// test time, and its tear-down follows the start.
func TestLabPhases(t *testing.T) {
	queued := time.Date(2026, 11, 19, 8, 0, 0, 0, time.UTC)
	at := func(d time.Duration) time.Time { return queued.Add(d) }
	began := at(30 * time.Second)
	got := labPhases(queued, began, at(100*time.Second), at(105*time.Second), at(108*time.Second), time.Minute)
	want := LabPhases{Queue: 30 * time.Second, SlotWait: time.Minute, Start: 10 * time.Second, Tests: 5 * time.Second, Teardown: 3 * time.Second}
	if got != want {
		t.Errorf("phases %+v, want %+v", got, want)
	}
	if sum := got.Queue + got.SlotWait + got.Start + got.Tests + got.Teardown; sum != 108*time.Second {
		t.Errorf("phases add up to %v, want the run's 1m48s", sum)
	}
	got = labPhases(began, began, at(80*time.Second), time.Time{}, at(82*time.Second), 45*time.Second)
	want = LabPhases{SlotWait: 45 * time.Second, Start: 5 * time.Second, Teardown: 2 * time.Second}
	if got != want {
		t.Errorf("a failed start: %+v, want %+v", got, want)
	}
	got = labPhases(began, began, at(80*time.Second), time.Time{}, time.Time{}, 50*time.Second)
	if want = (LabPhases{SlotWait: 50 * time.Second}); got != want {
		t.Errorf("no slot, no lab: %+v, want %+v", got, want)
	}
}

// TestLabTimerTimesTheSlotWait: the clock a package's lab start gets from
// its timer notes the start's slot wait, and the timer's phases have it
// apart from the package's queue and the rest of the start.
func TestLabTimerTimesTheSlotWait(t *testing.T) {
	t.Setenv("TMPDIR", t.TempDir())
	t.Setenv(MaxLabsEnv, "1")
	ctx := context.Background()
	held, err := waitForSlot(ctx, labBudget.begin(time.Time{}), "tplab-x-t-a", "")
	if err != nil {
		t.Fatal(err)
	}
	const hold, queue = 300 * time.Millisecond, 2 * time.Second
	go func() {
		time.Sleep(hold)
		held()
	}()
	now := time.Now()
	timer := labTimer{queued: now.Add(-queue), began: now}
	release, err := waitForSlot(ctx, timer.startClock(), "tplab-x-t-b", "")
	if err != nil {
		t.Fatal(err)
	}
	release()
	timer.started = time.Now()
	p := timer.phases(timer.started)
	if p.Queue != queue || p.SlotWait < hold || p.SlotWait > time.Minute || p.Start > 100*time.Millisecond {
		t.Errorf("phases %+v: want a %v queue, a slot wait of at least %v, a start of little more", p, queue, hold)
	}
}

// TestLabTimeLine: the node phase's line for a package gives its time and
// the five phases apart.
func TestLabTimeLine(t *testing.T) {
	p := LabPhases{Queue: 5 * time.Second, SlotWait: 2*time.Minute + 3*time.Second, Start: 12340 * time.Millisecond, Tests: 4100 * time.Millisecond, Teardown: 3 * time.Second}
	got := labTimeLine("example.net/m/pkg", 2*time.Minute+27440*time.Millisecond, p)
	want := "lab gotest example.net/m/pkg: took 2m27.4s (queue 5s, slot wait 2m3s, lab start 12.3s, tests 4.1s, teardown 3s)\n"
	if got != want {
		t.Errorf("line %q, want %q", got, want)
	}
}

// TestFreshLabMarksSayWhat: every FreshLabFile in the module holds only
// its package clause and a comment saying what the package's tests change
// that the reset doesn't read (freshLabMarkProblem).
func TestFreshLabMarksSayWhat(t *testing.T) {
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	marks, err := freshLabMarks(root)
	if err != nil {
		t.Fatal(err)
	}
	var marked []string
	for _, m := range marks {
		marked = append(marked, filepath.ToSlash(filepath.Dir(m.rel)))
		if m.problem != "" {
			t.Errorf("%s: %s", m.rel, m.problem)
		}
	}
	t.Logf("packages on fresh labs: %v", marked)
}

// TestFreshLabMarksSkipTheRunBinaries: the walk for FreshLabFile stays out
// of lab/bin. The run's other phases write there while ./lab's in-node pass
// runs, and a directory the pass listed that changed during it keeps the
// pass from being recorded in the node phase's cache.
func TestFreshLabMarksSkipTheRunBinaries(t *testing.T) {
	root := t.TempDir()
	for _, dir := range []string{"pkg", filepath.Join("lab", "bin", "run-x", "tests")} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, dir, FreshLabFile), []byte("package x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	marks, err := freshLabMarks(root)
	if err != nil {
		t.Fatal(err)
	}
	var rels []string
	for _, m := range marks {
		rels = append(rels, filepath.ToSlash(m.rel))
		// The fixture has no comment: a mark read without its source
		// would pass for a good one.
		if m.problem == "" {
			t.Errorf("%s: no problem reported for a mark without a comment", m.rel)
		}
	}
	if want := []string{"pkg/" + FreshLabFile}; !slices.Equal(rels, want) {
		t.Errorf("marks found %v, want %v", rels, want)
	}
}

type freshLabMark struct{ rel, problem string }

// freshLabMarks reads every FreshLabFile in the checkout at root.
func freshLabMarks(root string) ([]freshLabMark, error) {
	var marks []freshLabMark
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && path != root && (strings.HasPrefix(d.Name(), ".") || d.Name() == "testdata" || path == binRoot(root)) {
			return filepath.SkipDir
		}
		if d.Name() != FreshLabFile {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		marks = append(marks, freshLabMark{rel, freshLabMarkProblem(src)})
		return nil
	})
	return marks, err
}

func TestFreshLabMarkProblem(t *testing.T) {
	for _, c := range []struct{ src, want string }{
		{"// Its tests write kernel.* sysctls, which the reset doesn't read.\npackage x_test\n", ""},
		{"package x\n\n// The tests change /usr/share, which the reset doesn't read.\n", ""},
		{"package x\n", "no comment saying what its tests change that the reset doesn't read"},
		{"//\npackage x // \n", "no comment saying what its tests change that the reset doesn't read"},
		{"// Why.\npackage x\n\nfunc init() {}\n", "holds more than its package clause and a comment"},
		{"// Why.\npackage x\n\nimport _ \"os\"\n", "holds more than its package clause and a comment"},
		{"not go", "doesn't parse"},
	} {
		if got := freshLabMarkProblem([]byte(c.src)); !strings.HasPrefix(got, c.want) || (c.want == "") != (got == "") {
			t.Errorf("%q: %q, want %q", c.src, got, c.want)
		}
	}
}

// freshLabMarkProblem is what is wrong with a FreshLabFile's source src,
// or "".
func freshLabMarkProblem(src []byte) string {
	f, err := parser.ParseFile(token.NewFileSet(), FreshLabFile, src, parser.ParseComments)
	if err != nil {
		return fmt.Sprintf("doesn't parse: %v", err)
	}
	if len(f.Decls) > 0 {
		return "holds more than its package clause and a comment"
	}
	for _, c := range f.Comments {
		if strings.TrimSpace(c.Text()) != "" {
			return ""
		}
	}
	return "no comment saying what its tests change that the reset doesn't read"
}
