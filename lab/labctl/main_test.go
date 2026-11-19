package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
	"github.com/KucherenkoIvan/thinkpol-vpn/lab/testcache"
)

func TestGotestVerdict(t *testing.T) {
	passed := lab.GoTestResult{ImportPath: "x/a", Tests: lab.TestTally{Passed: 2}}
	skipped := lab.GoTestResult{ImportPath: "x/b", Tests: lab.TestTally{Skipped: 1}}
	failed := lab.GoTestResult{ImportPath: "x/c", Failed: true, Tests: lab.TestTally{Failed: 1}}
	noneRan := lab.GoTestResult{ImportPath: "x/d"}
	for _, tc := range []struct {
		name        string
		results     []lab.GoTestResult
		failSkipped bool
		wantErr     []string // substrings; none: the run passes
	}{
		{"all skipped, lab-test", []lab.GoTestResult{skipped}, false, nil},
		{"all skipped, lab-gotest", []lab.GoTestResult{passed, skipped}, true, []string{"every test skipped in: x/b"}},
		{"skipped in the node, run on the host", []lab.GoTestResult{skipped, {ImportPath: "x/b", Tests: lab.TestTally{Passed: 1}}}, true, nil},
		{"run matched nothing in one package", []lab.GoTestResult{passed, noneRan}, true, nil},
		{"no test ran", []lab.GoTestResult{noneRan}, true, []string{"no test ran"}},
		{"no test ran, lab-test", []lab.GoTestResult{noneRan}, false, nil},
		{"failure and skips", []lab.GoTestResult{failed, skipped}, true, []string{"failed: x/c", "every test skipped in: x/b"}},
		{"failure", []lab.GoTestResult{failed}, false, []string{"failed: x/c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := gotestVerdict(tc.results, tc.failSkipped)
			if len(tc.wantErr) == 0 {
				if err != nil {
					t.Fatalf("gotestVerdict: %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("gotestVerdict: nil, want an error with %q", tc.wantErr)
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("gotestVerdict: %v, want it to contain %q", err, want)
				}
			}
		})
	}
}

func TestGotestWithNoPackagesWithTests(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the go command")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command here") // a lab node has test binaries but no toolchain
	}
	t.Setenv("GOWORK", "off")
	t.Setenv("GOFLAGS", "-mod=mod")
	root := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":         "module example.net/notests\n\ngo 1.26\n",
		"plain/plain.go": "package plain\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	patterns := []string{"./..."}
	if err := gotest(t.Context(), root, gotestOptions{tagged: true}, nil, nil, patterns); err != nil {
		t.Errorf("without -fail-skipped: %v, want nil", err)
	}
	err := gotest(t.Context(), root, gotestOptions{tagged: true, failSkipped: true}, nil, nil, patterns)
	if err == nil || !strings.Contains(err.Error(), "no packages with tests") {
		t.Errorf("with -fail-skipped: %v, want a no-packages error", err)
	}
}

// labctl down -run with an empty or invalid id (-run "$THINKPOL_LAB_RUN",
// the variable unset) fails before asking Docker anything, instead of
// becoming a plain down that removes every lab of the checkout.
func TestDownRunRejectsABadIDBeforeDocker(t *testing.T) {
	called := fakeDockerMarker(t)
	root := t.TempDir()

	for _, id := range []string{"", "Bad-ID", "r1-x", "123456789"} {
		if err := down(t.Context(), root, []string{"-run", id}); err == nil {
			t.Errorf("down -run %q: no error", id)
		}
		if _, err := os.Stat(called); err == nil {
			t.Fatalf("down -run %q asked Docker", id)
		}
	}
}

// labctl down with a positional argument (down r1 -run r1, or down r1 with
// -run forgotten) fails before asking Docker anything: flag parsing stops at
// the argument, so -run would go unseen and the whole checkout's labs go.
func TestDownRejectsPositionalArgumentsBeforeDocker(t *testing.T) {
	called := fakeDockerMarker(t)
	root := t.TempDir()

	for _, args := range [][]string{{"r1"}, {"r1", "-run", "r1"}, {"-tests", "r1"}} {
		if err := down(t.Context(), root, args); err == nil {
			t.Errorf("down %q: no error", args)
		}
		if _, err := os.Stat(called); err == nil {
			t.Fatalf("down %q asked Docker", args)
		}
	}
}

// fakeDockerMarker puts a failing docker on PATH that creates the file it
// returns when called.
func fakeDockerMarker(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	called := filepath.Join(dir, "called")
	script := "#!/bin/sh\ntouch '" + called + "'\necho fake docker >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return called
}

func TestUseCache(t *testing.T) {
	for _, tc := range []struct {
		name    string
		count   int
		perf    bool
		noCache string
		want    bool
	}{
		{"default", 0, false, "", true},
		{"-count=1", 1, false, "", false},
		{"-count=3", 3, false, "", false},
		{"-perf", 0, true, "", false},
		{"LAB_NOCACHE=1", 0, false, "1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(testcache.NoCacheEnv, tc.noCache)
			if got := useCache(tc.count, tc.perf); got != tc.want {
				t.Fatalf("useCache = %v, want %v", got, tc.want)
			}
		})
	}
}

// writeModule writes files, by slash-separated path, under a fresh root.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
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

// TestGotestSkipAndTimes: gotest -skip reaches the test binaries (a
// lab-tagged package's failing test skipped, the run passes), and -times
// writes how long each package took.
func TestGotestSkipAndTimes(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the go command")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command here")
	}
	t.Setenv("GOWORK", "off")
	t.Setenv("GOFLAGS", "-mod=mod")
	t.Setenv(testcache.NoCacheEnv, "1") // the user's own cache stays as it is
	root := writeModule(t, map[string]string{
		"go.mod": "module example.net/skip\n\ngo 1.26\n",
		"tagged/tagged_test.go": "//go:build lab\n\npackage tagged\n\nimport \"testing\"\n\n" +
			"func TestKeep(t *testing.T) {}\n\nfunc TestDrop(t *testing.T) { t.Fatal(\"not skipped\") }\n",
	})
	if err := runGotest(t.Context(), root, []string{"-tagged", "./..."}); err == nil {
		t.Fatal("without -skip: passed, want TestDrop's failure")
	}
	times := filepath.Join(t.TempDir(), "times")
	if err := runGotest(t.Context(), root, []string{"-tagged", "-skip", "^TestDrop$", "-times", times, "./..."}); err != nil {
		t.Fatalf("with -skip: %v", err)
	}
	got, err := lab.ReadTestTimes(times)
	if err != nil || len(got) != 1 || got[0].Name != "example.net/skip/tagged" || got[0].Elapsed <= 0 {
		t.Fatalf("times: %v, %v", got, err)
	}
}

// TestGotestRunFor: a phase's bound is an hour, or 15 minutes past its
// test binaries' timeout (given, or the phase's default) when longer; a
// timeout of 0 gives none.
func TestGotestRunFor(t *testing.T) {
	for _, tc := range []struct {
		timeout, def string
		want         time.Duration
		ok           bool
	}{
		{"", "10m", time.Hour, true},
		{"", "60m", 75 * time.Minute, true},
		{"10m", "60m", time.Hour, true},
		{"2h", "10m", 2*time.Hour + 15*time.Minute, true},
		{"0", "10m", 0, true},
		{"soon", "10m", 0, false},
	} {
		got, err := gotestRunFor(tc.timeout, tc.def)
		if got != tc.want || (err == nil) != tc.ok {
			t.Errorf("gotestRunFor(%q, %q) = %v, %v; want %v", tc.timeout, tc.def, got, err, tc.want)
		}
	}
}

// TestBudget: labctl budget passes a stream within its budget, fails one
// over it and lists its slowest tests from every times file, and says when
// a times file is missing from that list.
func TestBudget(t *testing.T) {
	dir := t.TempDir()
	labTimes, nodeTimes := filepath.Join(dir, "lab.times"), filepath.Join(dir, "node.times")
	if err := lab.WriteTestTimes(labTimes, []lab.TestTime{{Name: "lab TestSlow", Elapsed: 9 * time.Minute}}); err != nil {
		t.Fatal(err)
	}
	if err := lab.WriteTestTimes(nodeTimes, []lab.TestTime{{Name: "example.net/m/pkg", Elapsed: 4 * time.Minute}}); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(100_000, 0)
	since := func(d time.Duration) string { return strconv.FormatInt(now.Add(-d).Unix(), 10) }
	var w bytes.Buffer
	if err := budget(&w, now, []string{"-stream", "default", "-since", since(10 * time.Minute), "-budget", "15m", labTimes, nodeTimes}); err != nil {
		t.Errorf("within budget: %v (%s)", err, w.String())
	}
	w.Reset()
	over := filepath.Join(dir, "over")
	err := budget(&w, now, []string{"-stream", "default", "-since", since(20 * time.Minute), "-budget", "15m", "-over", over, labTimes, nodeTimes})
	if err == nil || !strings.Contains(w.String(), "lab TestSlow") || !strings.Contains(w.String(), "example.net/m/pkg") {
		t.Errorf("over budget: %v, report:\n%s", err, w.String())
	}
	if b, err := os.ReadFile(over); err != nil || string(b) != "20m0s > 15m0s\n" {
		t.Errorf("-over file: %q, %v", b, err)
	}
	w.Reset()
	err = budget(&w, now, []string{"-stream", "default", "-since", since(20 * time.Minute), "-budget", "15m", labTimes, filepath.Join(dir, "gone.times")})
	if err == nil || !strings.Contains(err.Error(), "misses tests") {
		t.Errorf("over budget, a times file missing: %v", err)
	}
	if err := budget(&w, now, []string{"-stream", "default", "-budget", "15m"}); err == nil {
		t.Error("no -since: passed")
	}
}

// TestBudgetRejectsBadBudgets: an empty or negative budget is an error,
// with -check before anything runs and in the check itself, and an empty
// one doesn't take the next argument for its value; 0 is none.
func TestBudgetRejectsBadBudgets(t *testing.T) {
	now := time.Unix(100_000, 0)
	since := strconv.FormatInt(now.Add(-time.Hour).Unix(), 10)
	var w bytes.Buffer
	for _, b := range []string{"-budget=", "-budget=-5m", "-budget=soon"} {
		if err := budget(&w, now, []string{"-check", b}); err == nil {
			t.Errorf("-check %s: passed", b)
		}
		if err := budget(&w, now, []string{"-stream", "default", "-since", since, b}); err == nil {
			t.Errorf("%s: passed", b)
		}
	}
	if err := budget(&w, now, []string{"-check", "-budget=0"}); err != nil {
		t.Errorf("-check -budget=0: %v", err)
	}
	if err := budget(&w, now, []string{"-check"}); err == nil {
		t.Error("-check without -budget: passed")
	}
	w.Reset()
	if err := budget(&w, now, []string{"-stream", "default", "-since", since, "-budget=0"}); err != nil || !strings.Contains(w.String(), "took 1h0m0s\n") {
		t.Errorf("-budget=0: %v, %q", err, w.String())
	}
}

// TestTestJSONWritesTimes: labctl testjson writes the tests' times, and
// wants -times.
func TestTestJSONWritesTimes(t *testing.T) {
	times := filepath.Join(t.TempDir(), "times")
	in := `{"Action":"pass","Package":"x/lab","Test":"TestA","Elapsed":2.5}` + "\n"
	var w bytes.Buffer
	if err := testJSON(strings.NewReader(in), &w, []string{"-times", times}); err != nil {
		t.Fatal(err)
	}
	got, err := lab.ReadTestTimes(times)
	if err != nil || len(got) != 1 || got[0] != (lab.TestTime{Name: "lab TestA", Elapsed: 2500 * time.Millisecond}) {
		t.Fatalf("times: %v, %v", got, err)
	}
	if err := testJSON(strings.NewReader(in), &w, nil); err == nil {
		t.Error("no -times: passed")
	}
}

// TestGotestTimesWhenALabFails: when labs fail (Docker fails), -times is
// still written, so the budget's report has the node phase when it needs
// it most; a package that never ran (its lab's preparation failed) has no
// line, rather than one of 0 s.
func TestGotestTimesWhenALabFails(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the go command")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command here")
	}
	fakeDockerMarker(t)
	t.Setenv("GOWORK", "off")
	t.Setenv("GOFLAGS", "-mod=mod")
	root := writeModule(t, map[string]string{
		"go.mod":              "module example.net/nolab\n\ngo 1.26\n",
		"plain/plain_test.go": "package plain\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n",
	})
	times := filepath.Join(t.TempDir(), "times")
	if err := runGotest(t.Context(), root, []string{"-times", times, "./..."}); err == nil {
		t.Fatal("passed with Docker failing")
	}
	got, err := lab.ReadTestTimes(times)
	if err != nil || len(got) != 0 {
		t.Fatalf("times: %v, %v; want the file, empty", got, err)
	}
}

// labctl gotest refuses -p or -build-p below one before it lists or starts
// anything, instead of running with a cap of its own choosing.
func TestGotestRejectsConcurrencyBelowOne(t *testing.T) {
	for _, args := range [][]string{{"-p", "0"}, {"-build-p", "0"}, {"-p", "-1"}} {
		err := runGotest(t.Context(), t.TempDir(), append(args, "./..."))
		if err == nil || !strings.Contains(err.Error(), "want 1 or more") {
			t.Errorf("gotest %v: %v, want a want-1-or-more error", args, err)
		}
	}
}

// TestGotestRunsNodelessPackagesOnTheHost: with nodelessOnHost, a package
// with lab.HostTestsFile runs on the host, starting no lab (Docker, which
// fails here, is never called), and its time is in -times; without it,
// the same package goes to a node.
func TestGotestRunsNodelessPackagesOnTheHost(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the go command")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command here")
	}
	called := fakeDockerMarker(t)
	t.Setenv("GOWORK", "off")
	t.Setenv("GOFLAGS", "-mod=mod")
	root := writeModule(t, map[string]string{
		"go.mod":                    "module example.net/hostrun\n\ngo 1.26\n",
		"host/host_test.go":         "package host\n\nimport \"testing\"\n\nfunc TestX(t *testing.T) {}\n",
		"host/" + lab.HostTestsFile: "package host\n",
	})
	times := filepath.Join(t.TempDir(), "times")
	opt := gotestOptions{concurrency: lab.GoTestConcurrency{Labs: 1, Builds: 1}, nodelessOnHost: true, times: times}
	if err := gotest(t.Context(), root, opt, nil, []string{"-test.count=1"}, []string{"./..."}); err != nil {
		t.Fatalf("on the host: %v", err)
	}
	if _, err := os.Stat(called); err == nil {
		t.Error("a package that needs no node called docker")
	}
	got, err := lab.ReadTestTimes(times)
	if err != nil || len(got) != 1 || got[0].Name != "example.net/hostrun/host" || got[0].Elapsed <= 0 || !got[0].Phases.IsZero() {
		t.Errorf("times: %+v, %v; want the host package's, without lab phases", got, err)
	}
	opt.nodelessOnHost = false
	if err := gotest(t.Context(), root, opt, nil, []string{"-test.count=1"}, []string{"./..."}); err == nil {
		t.Error("in a node, with Docker failing: passed")
	}
	if _, err := os.Stat(called); err != nil {
		t.Errorf("in a node: docker not called (%v)", err)
	}
}

// TestHostRunsNodeless: packages that need no node run on the host only
// on Linux, and never in a perf run.
func TestHostRunsNodeless(t *testing.T) {
	for _, tc := range []struct {
		goos string
		perf bool
		want bool
	}{{"linux", false, true}, {"linux", true, false}, {"darwin", false, false}, {"windows", false, false}} {
		if got := hostRunsNodeless(tc.goos, tc.perf); got != tc.want {
			t.Errorf("hostRunsNodeless(%q, %v) = %v, want %v", tc.goos, tc.perf, got, tc.want)
		}
	}
}

// TestWriteGotestTimesKeepsPhases: a node package's lab phases reach the
// times file the budget reads.
func TestWriteGotestTimesKeepsPhases(t *testing.T) {
	f := filepath.Join(t.TempDir(), "times")
	p := lab.LabPhases{SlotWait: time.Minute, Start: 20 * time.Second, Tests: 5 * time.Second, Teardown: 3 * time.Second}
	results := []lab.GoTestResult{
		{ImportPath: "example.net/m/node", Elapsed: 88 * time.Second, Phases: p},
		{ImportPath: "example.net/m/cached", Cached: true},
	}
	if err := writeGotestTimes(f, results); err != nil {
		t.Fatal(err)
	}
	got, err := lab.ReadTestTimes(f)
	if err != nil || len(got) != 1 || got[0] != (lab.TestTime{Name: "example.net/m/node", Elapsed: 88 * time.Second, Phases: p}) {
		t.Errorf("times: %+v, %v", got, err)
	}
}
