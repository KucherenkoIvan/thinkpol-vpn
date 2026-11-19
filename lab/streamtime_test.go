package lab

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// events renders test2json events, one JSON line each.
func events(t *testing.T, evs ...testEvent) string {
	t.Helper()
	var b strings.Builder
	for _, ev := range evs {
		line, err := json.Marshal(ev)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func outEvent(test, s string) testEvent {
	return testEvent{Action: "output", Package: "x/lab", Test: test, Output: s}
}

func endEvent(action, test string, secs float64) testEvent {
	return testEvent{Action: action, Package: "x/lab", Test: test, Elapsed: secs}
}

// TestFilterTestJSON: the filter prints what go test without -v would:
// lines outside tests as they come; a failed test's output with its failed
// subtests', not its passed ones' and without the === framing lines; a
// test that never ended before its package's verdict; nothing of a test
// that passed or skipped; interleaved parallel tests kept apart. It times
// top-level tests and their direct subtests that ended.
func TestFilterTestJSON(t *testing.T) {
	in := "go: downloading example.net/m v1.0.0\n" + events(t,
		outEvent("TestPass", "=== RUN   TestPass\n"),
		outEvent("TestPass", "    pass_test.go:1: quiet\n"),
		outEvent("TestPass", "--- PASS: TestPass (1.50s)\n"),
		endEvent("pass", "TestPass", 1.5),
		outEvent("TestFail", "=== RUN   TestFail\n"),
		outEvent("TestPar", "=== CONT  TestPar\n"),
		outEvent("TestFail", "    fail_test.go:5: setting up\n"),
		outEvent("TestFail/sub", "=== RUN   TestFail/sub\n"),
		outEvent("TestFail/sub", "    fail_test.go:9: broke\n"),
		outEvent("TestPar", "    par_test.go:3: par noise\n"),
		outEvent("TestFail/sub/deep", "    deep_test.go:1: deep noise\n"),
		outEvent("TestFail/sub/deep", "--- PASS: TestFail/sub/deep (0.10s)\n"),
		endEvent("pass", "TestFail/sub/deep", 0.1),
		outEvent("TestFail/sub", "--- FAIL: TestFail/sub (2.00s)\n"),
		endEvent("fail", "TestFail/sub", 2),
		outEvent("TestFail/ok", "    ok_test.go:1: fine\n"),
		outEvent("TestFail/ok", "--- PASS: TestFail/ok (0.50s)\n"),
		endEvent("pass", "TestFail/ok", 0.5),
		outEvent("TestFail", "--- FAIL: TestFail (3.00s)\n"),
		endEvent("fail", "TestFail", 3),
		endEvent("pass", "TestPar", 4),
		outEvent("TestSkip", "=== RUN   TestSkip\n"),
		outEvent("TestSkip", "    skip_test.go:2: needs the lab\n"),
		outEvent("TestSkip", "--- SKIP: TestSkip (0.00s)\n"),
		endEvent("skip", "TestSkip", 0),
		outEvent("TestHung", "=== RUN   TestHung\n"),
		outEvent("TestHung", "panic: test timed out\n"),
		outEvent("", "FAIL\tx/lab\t5.000s\n"),
		endEvent("fail", "", 5),
	)
	var w bytes.Buffer
	times, err := FilterTestJSON(strings.NewReader(in), &w, false)
	if err != nil {
		t.Fatal(err)
	}
	want := "go: downloading example.net/m v1.0.0\n" +
		"    fail_test.go:5: setting up\n    fail_test.go:9: broke\n--- FAIL: TestFail/sub (2.00s)\n--- FAIL: TestFail (3.00s)\n" +
		"panic: test timed out\n" +
		"FAIL\tx/lab\t5.000s\n"
	if w.String() != want {
		t.Errorf("printed:\n%s\nwant:\n%s", w.String(), want)
	}
	wantTimes := []TestTime{{Name: "lab TestPass", Elapsed: 1500 * time.Millisecond}, {Name: "lab TestFail/sub", Elapsed: 2 * time.Second}, {Name: "lab TestFail/ok", Elapsed: 500 * time.Millisecond}, {Name: "lab TestFail", Elapsed: 3 * time.Second}, {Name: "lab TestPar", Elapsed: 4 * time.Second}}
	if len(times) != len(wantTimes) {
		t.Fatalf("times %v, want %v", times, wantTimes)
	}
	for i := range times {
		if times[i] != wantTimes[i] {
			t.Errorf("time %d: %v, want %v", i, times[i], wantTimes[i])
		}
	}

	w.Reset()
	if _, err := FilterTestJSON(strings.NewReader(in), &w, true); err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"=== RUN   TestPass\n", "--- PASS: TestFail/sub/deep (0.10s)\n", "--- SKIP: TestSkip (0.00s)\n", "panic: test timed out\n"} {
		if !strings.Contains(w.String(), line) {
			t.Errorf("verbose: %q missing from:\n%s", line, w.String())
		}
	}
}

// TestFilterTestJSONFailingCellKept: a failing subtest's error is printed
// even when its passing siblings wrote far more than the failed parent's
// printed head and tail hold, as the censor matrix's cells do.
func TestFilterTestJSONFailingCellKept(t *testing.T) {
	noise := strings.Repeat("noise\n", testLogKeep/6)
	var evs []testEvent
	for i := range 6 {
		cell := "TestMatrix/row/cell" + strconv.Itoa(i)
		evs = append(evs, outEvent(cell, noise))
		if i == 3 {
			evs = append(evs, outEvent(cell, "    cell_test.go:7: THE ERROR\n"), endEvent("fail", cell, 1))
		} else {
			evs = append(evs, endEvent("pass", cell, 1))
		}
	}
	evs = append(evs, endEvent("fail", "TestMatrix/row", 6), endEvent("fail", "TestMatrix", 6))
	var w bytes.Buffer
	if _, err := FilterTestJSON(strings.NewReader(events(t, evs...)), &w, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.String(), "THE ERROR") || strings.Contains(w.String(), "bytes of this test's output cut") || w.Len() > 2*testLogKeep {
		t.Errorf("printed %d bytes, error kept %v", w.Len(), strings.Contains(w.String(), "THE ERROR"))
	}
}

// TestFilterTestJSONUnended: tests that never ended are printed whole,
// however long (a timeout's goroutine dump), in name order, before their
// package's verdict, and untimed; so is one test2json failed for its
// binary dying; one whose binary died with no verdict when the input ends.
func TestFilterTestJSONUnended(t *testing.T) {
	dump := "goroutine 1 [running]:\n" + strings.Repeat("\tframe\n", 3*testLogKeep/7) + "END OF DUMP\n"
	names := []string{"TestH", "TestC", "TestF", "TestA", "TestG", "TestB", "TestE", "TestD"}
	var evs []testEvent
	for _, n := range names {
		evs = append(evs, outEvent(n, n+" started\n"))
	}
	evs = append(evs, outEvent("TestD", dump), outEvent("", "FAIL\tx/lab\t5.000s\n"), endEvent("fail", "", 5))
	// test2json running the binary itself fails the test that was running
	// when it died, with no "--- FAIL" line from the testing package.
	evs = append(evs, outEvent("TestKilled", "TestKilled started\n"), outEvent("TestKilled", dump), endEvent("fail", "TestKilled", 0))
	var w bytes.Buffer
	times, err := FilterTestJSON(strings.NewReader(events(t, evs...)), &w, false)
	if err != nil {
		t.Fatal(err)
	}
	s := w.String()
	if !strings.Contains(s, "TestD started\n"+dump) {
		t.Errorf("the dump was not printed whole (%d bytes printed)", len(s))
	}
	last := -1
	for _, n := range slices.Sorted(slices.Values(names)) {
		i := strings.Index(s, n+" started\n")
		if i < last {
			t.Errorf("%s printed out of name order", n)
		}
		last = i
	}
	verdict := strings.Index(s, "FAIL\tx/lab\t5.000s\n")
	if verdict < last {
		t.Error("the package's verdict came before its unended tests")
	}
	if !strings.HasSuffix(s, "TestKilled started\n"+dump) {
		t.Errorf("a test failed by test2json, not by its own --- FAIL line, was not printed whole (%d bytes printed)", len(s))
	}
	if len(times) != 0 {
		t.Errorf("tests that never ended were timed: %v", times)
	}

	w.Reset()
	if _, err := FilterTestJSON(strings.NewReader(events(t, outEvent("TestHung", "last words\n"))), &w, false); err != nil {
		t.Fatal(err)
	}
	if w.String() != "last words\n" {
		t.Errorf("at EOF, printed %q", w.String())
	}
}

// TestReadLineCut: a line over the bound is cut, still ends a line, and
// the next line reads whole.
func TestReadLineCut(t *testing.T) {
	br := bufio.NewReaderSize(strings.NewReader(strings.Repeat("a", 100)+"\nnext\ntail"), 16)
	for _, want := range []string{strings.Repeat("a", 40) + "\n", "next\n", "tail"} {
		line, err := readLine(br, 40)
		if string(line) != want || (err != nil && err != io.EOF) {
			t.Fatalf("line %q, %v; want %q", line, err, want)
		}
	}
}

// TestTestLogBounded: a test's output is held whole, spilling to a file
// past testLogMem, and printed whole or as its head and tail with how much
// was cut between them.
func TestTestLogBounded(t *testing.T) {
	var l testLog
	defer l.close()
	whole := "HEAD" + strings.Repeat("h", testLogKeep) + strings.Repeat("m", 5*testLogKeep/2) + strings.Repeat("t", testLogKeep-4) + "TAIL"
	for chunk := range slices.Chunk([]byte(whole), 4096) {
		if err := l.write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if len(l.mem) > testLogMem || l.file == nil {
		t.Fatalf("holds %d bytes in memory, spilled %v", len(l.mem), l.file != nil)
	}
	var w bytes.Buffer
	if err := l.writeTo(&w, true); err != nil || w.String() != whole {
		t.Fatalf("whole: %d bytes, %v; want %d", w.Len(), err, len(whole))
	}
	w.Reset()
	if err := l.writeTo(&w, false); err != nil {
		t.Fatal(err)
	}
	s := w.String()
	cut := len(whole) - 2*testLogKeep
	if !strings.HasPrefix(s, "HEAD") || !strings.HasSuffix(s, "TAIL") || !strings.Contains(s, "("+strconv.Itoa(cut)+" bytes of this test's output cut)") {
		t.Errorf("head %q, tail %q, cut note missing (want %d cut)", s[:8], s[len(s)-8:], cut)
	}
}

func TestTestTimesRoundTrip(t *testing.T) {
	f := filepath.Join(t.TempDir(), "times")
	in := []TestTime{{Name: "lab TestA", Elapsed: 1500 * time.Millisecond}, {Name: "example.net/m/pkg", Elapsed: 90 * time.Second}}
	if err := WriteTestTimes(f, in); err != nil {
		t.Fatal(err)
	}
	got, err := ReadTestTimes(f)
	if err != nil || len(got) != 2 || got[0] != in[0] || got[1] != in[1] {
		t.Fatalf("read %v, %v; want %v", got, err, in)
	}
}

// TestTestTimesRoundTripPhases: a node-phase package's phases go through
// the times file beside lines without them; a line with phases other than
// five is refused.
func TestTestTimesRoundTripPhases(t *testing.T) {
	f := filepath.Join(t.TempDir(), "times")
	in := []TestTime{
		{Name: "example.net/m/pkg", Elapsed: 90 * time.Second, Phases: LabPhases{Queue: 7 * time.Second, SlotWait: time.Minute, Start: 20 * time.Second, Tests: 7500 * time.Millisecond, Teardown: 2500 * time.Millisecond}},
		{Name: "lab TestA", Elapsed: 1500 * time.Millisecond},
	}
	if err := WriteTestTimes(f, in); err != nil {
		t.Fatal(err)
	}
	got, err := ReadTestTimes(f)
	if err != nil || !slices.Equal(got, in) {
		t.Fatalf("read %+v, %v; want %+v", got, err, in)
	}
	for _, bad := range []string{"1.000\tx\t1 2 3 4\n", "1.000\tx\t1 2 3 4 soon\n", "1.000\n"} {
		if err := os.WriteFile(f, []byte(bad), 0o644); err != nil {
			t.Fatal(err)
		}
		if got, err := ReadTestTimes(f); err == nil {
			t.Errorf("%q read as %+v", bad, got)
		}
	}
}

// TestCheckBudgetPhases: the report sums the node phase's packages'
// phases, within the budget too, and over it shows each listed package's
// own; tests without phases add nothing to the sum.
func TestCheckBudgetPhases(t *testing.T) {
	times := []TestTime{
		{Name: "lab TestA", Elapsed: 4 * time.Minute},
		{Name: "pkg/b", Elapsed: 5 * time.Minute, Phases: LabPhases{Queue: 20 * time.Second, SlotWait: 3*time.Minute + 40*time.Second, Start: 40 * time.Second, Tests: 15 * time.Second, Teardown: 5 * time.Second}},
		{Name: "pkg/c", Elapsed: time.Minute, Phases: LabPhases{Queue: 10 * time.Second, SlotWait: 20 * time.Second, Start: 20 * time.Second, Tests: 5 * time.Second, Teardown: 5 * time.Second}},
	}
	sum := "  node phase, 2 packages in labs, summed: queue 30s, slot wait 4m0s, lab start 1m0s, tests 20s, teardown 10s\n"
	var w bytes.Buffer
	if err := CheckBudget(&w, "default", 10*time.Minute, 15*time.Minute, times, 3); err != nil || w.String() != "the default stream took 10m0s of its 15m0s budget\n"+sum {
		t.Errorf("within budget: %v, %q", err, w.String())
	}
	w.Reset()
	if err := CheckBudget(&w, "default", 16*time.Minute, 15*time.Minute, times, 3); err == nil ||
		!strings.Contains(w.String(), "pkg/b (queue 20s, slot wait 3m40s, lab start 40s, tests 15s, teardown 5s)\n") ||
		!strings.Contains(w.String(), "lab TestA\n") || !strings.HasSuffix(w.String(), sum) {
		t.Errorf("over budget: %v, report:\n%s", err, w.String())
	}
}

// TestCheckBudget: within the budget the stream's time is reported; over
// it the check fails and lists the slowest tests, slowest first, at most
// top of them; with no budget it only reports.
func TestCheckBudget(t *testing.T) {
	times := []TestTime{{Name: "lab TestA", Elapsed: time.Minute}, {Name: "lab TestB", Elapsed: 5 * time.Minute}, {Name: "pkg/c", Elapsed: 3 * time.Minute}, {Name: "lab TestD", Elapsed: time.Second}, {Name: "lab TestM/r", Elapsed: 30 * time.Second}, {Name: "lab TestM", Elapsed: 9 * time.Minute}}
	var w bytes.Buffer
	if err := CheckBudget(&w, "default", 14*time.Minute, 15*time.Minute, times, 3); err != nil || !strings.Contains(w.String(), "took 14m0s of its 15m0s budget") {
		t.Errorf("within budget: %v, %q", err, w.String())
	}
	w.Reset()
	err := CheckBudget(&w, "default", 15*time.Minute+time.Second, 15*time.Minute, times, 3)
	report := w.String()
	var over *OverBudgetError
	if !errors.As(err, &over) || over.Took != 15*time.Minute+time.Second || over.Budget != 15*time.Minute {
		t.Errorf("over budget: %v, report %q", err, report)
	}
	b, c, a := strings.Index(report, "lab TestB"), strings.Index(report, "pkg/c"), strings.Index(report, "lab TestA")
	if !strings.Contains(report, "took 15m1s, over its 15m0s budget") || b < 0 || c < b || a < c || strings.Contains(report, "TestD") || strings.Contains(report, "lab TestM ") || strings.Contains(report, "lab TestM\n") {
		t.Errorf("over budget report:\n%s", report)
	}
	w.Reset()
	if err := CheckBudget(&w, "long", 2*time.Hour, 0, times, 3); err != nil || w.String() != "the long stream took 2h0m0s\n" {
		t.Errorf("no budget: %v, %q", err, w.String())
	}
}

// TestParseBudget: a budget is a Go duration, 0 for none; empty or
// negative is refused, not taken as none.
// TestSlowestTestsPackages: a package's line is never taken for a parent,
// though its import path has a "/" in it: a slow package beside a
// subpackage stays on the list. A test with timed subtests is left out.
func TestSlowestTestsPackages(t *testing.T) {
	times := []TestTime{
		{Name: "example.net/m/internal/agent", Elapsed: 5 * time.Minute},
		{Name: "example.net/m/internal/agent/supervisor", Elapsed: time.Minute},
		{Name: "example.net/m/lab/ip TestX", Elapsed: 4 * time.Minute},
		{Name: "example.net/m/lab/ip TestX/a", Elapsed: 3 * time.Minute},
		{Name: "example.net/m/lab/ip TestX/a/b", Elapsed: 2 * time.Minute},
	}
	var got []string
	for _, tt := range SlowestTests(times, 10) {
		got = append(got, tt.Name)
	}
	want := []string{"example.net/m/internal/agent", "example.net/m/lab/ip TestX/a/b", "example.net/m/internal/agent/supervisor"}
	if !slices.Equal(got, want) {
		t.Errorf("SlowestTests = %q, want %q", got, want)
	}
}

func TestParseBudget(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want time.Duration
		ok   bool
	}{{"15m", 15 * time.Minute, true}, {"0", 0, true}, {"", 0, false}, {"-1m", 0, false}, {"soon", 0, false}} {
		got, err := ParseBudget(tc.in)
		if got != tc.want || (err == nil) != tc.ok {
			t.Errorf("ParseBudget(%q) = %v, %v", tc.in, got, err)
		}
	}
}

// TestMakefileTimesLabBinary: every test2json a Makefile recipe runs a
// test binary under has -t: without timestamps it leaves Elapsed out of its
// events, and the budget's report would miss those tests.
func TestMakefileTimesLabBinary(t *testing.T) {
	mk, err := os.ReadFile(filepath.Join("..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	runs := regexp.MustCompile(`(?m)^\t.*(go tool test2json[^|;)]*)`).FindAllSubmatch(mk, -1)
	if len(runs) == 0 {
		t.Fatal("the Makefile runs no test2json")
	}
	for _, r := range runs {
		if !regexp.MustCompile(` -t( |$)`).Match(r[1]) {
			t.Errorf("test2json without -t: %s", r[1])
		}
	}
}

func TestStream(t *testing.T) {
	for _, tc := range []struct {
		env, want string
		ok        bool
	}{{"", "", true}, {"default", StreamDefault, true}, {"long", StreamLong, true}, {"Long", "", false}, {"both", "", false}} {
		t.Setenv(StreamEnv, tc.env)
		got, err := Stream()
		if got != tc.want || (err == nil) != tc.ok {
			t.Errorf("%s=%q: %q, %v", StreamEnv, tc.env, got, err)
		}
	}
}
