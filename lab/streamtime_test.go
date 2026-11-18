package lab

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"path/filepath"
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

func out(test, s string) testEvent {
	return testEvent{Action: "output", Package: "x/lab", Test: test, Output: s}
}

func end(action, test string, secs float64) testEvent {
	return testEvent{Action: action, Package: "x/lab", Test: test, Elapsed: secs}
}

// TestFilterTestJSON: the filter prints what go test without -v would:
// lines outside tests as they come, a failed test's output whole, a test
// that never ended before its package's verdict, nothing of a test that
// passed or skipped, interleaved parallel tests kept apart; and it times top-level
// tests and their direct subtests that ended.
func TestFilterTestJSON(t *testing.T) {
	in := "go: downloading example.net/m v1.0.0\n" + events(t,
		out("TestPass", "=== RUN   TestPass\n"),
		out("TestPass", "    pass_test.go:1: quiet\n"),
		out("TestPass", "--- PASS: TestPass (1.50s)\n"),
		end("pass", "TestPass", 1.5),
		out("TestFail", "=== RUN   TestFail\n"),
		out("TestPar", "=== CONT  TestPar\n"),
		out("TestFail/sub", "    fail_test.go:9: broke\n"),
		out("TestPar", "    par_test.go:3: par noise\n"),
		out("TestFail/sub/deep", "--- PASS: TestFail/sub/deep (0.10s)\n"),
		end("pass", "TestFail/sub/deep", 0.1),
		out("TestFail/sub", "--- FAIL: TestFail/sub (2.00s)\n"),
		end("fail", "TestFail/sub", 2),
		out("TestFail", "--- FAIL: TestFail (3.00s)\n"),
		end("fail", "TestFail", 3),
		end("pass", "TestPar", 4),
		out("TestSkip", "=== RUN   TestSkip\n"),
		out("TestSkip", "    skip_test.go:2: needs the lab\n"),
		out("TestSkip", "--- SKIP: TestSkip (0.00s)\n"),
		end("skip", "TestSkip", 0),
		out("TestHung", "=== RUN   TestHung\n"),
		out("TestHung", "panic: test timed out\n"),
		out("", "FAIL\tx/lab\t5.000s\n"),
		end("fail", "", 5),
	)
	var w bytes.Buffer
	times, err := FilterTestJSON(strings.NewReader(in), &w)
	if err != nil {
		t.Fatal(err)
	}
	want := "go: downloading example.net/m v1.0.0\n" +
		"=== RUN   TestFail\n    fail_test.go:9: broke\n--- PASS: TestFail/sub/deep (0.10s)\n--- FAIL: TestFail/sub (2.00s)\n--- FAIL: TestFail (3.00s)\n" +
		"=== RUN   TestHung\npanic: test timed out\n" +
		"FAIL\tx/lab\t5.000s\n"
	if w.String() != want {
		t.Errorf("printed:\n%s\nwant:\n%s", w.String(), want)
	}
	wantTimes := []TestTime{{"lab TestPass", 1500 * time.Millisecond}, {"lab TestFail/sub", 2 * time.Second}, {"lab TestFail", 3 * time.Second}, {"lab TestPar", 4 * time.Second}}
	if len(times) != len(wantTimes) {
		t.Fatalf("times %v, want %v", times, wantTimes)
	}
	for i := range times {
		if times[i] != wantTimes[i] {
			t.Errorf("time %d: %v, want %v", i, times[i], wantTimes[i])
		}
	}
}

// TestFilterTestJSONUnendedAtEOF: a test whose binary died with no package
// verdict is printed when the input ends.
func TestFilterTestJSONUnendedAtEOF(t *testing.T) {
	var w bytes.Buffer
	if _, err := FilterTestJSON(strings.NewReader(events(t, out("TestHung", "last words\n"))), &w); err != nil {
		t.Fatal(err)
	}
	if w.String() != "last words\n" {
		t.Errorf("printed %q", w.String())
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

// TestTestLogBounded: a test's output is kept as its head and its tail,
// with how much was cut between them.
func TestTestLogBounded(t *testing.T) {
	var l testLog
	l.write("HEAD" + strings.Repeat("h", testLogKeep))
	for range 5 {
		l.write(strings.Repeat("m", testLogKeep/2))
	}
	l.write(strings.Repeat("t", testLogKeep-4) + "TAIL")
	if len(l.head)+len(l.tail) > 3*testLogKeep {
		t.Fatalf("holds %d bytes", len(l.head)+len(l.tail))
	}
	var w bytes.Buffer
	if err := l.writeTo(&w); err != nil {
		t.Fatal(err)
	}
	s := w.String()
	cut := 4 + testLogKeep + 5*testLogKeep/2 + testLogKeep - 2*testLogKeep
	if !strings.HasPrefix(s, "HEAD") || !strings.HasSuffix(s, "TAIL") || !strings.Contains(s, "("+strconv.Itoa(cut)+" bytes of this test's output cut)") {
		t.Errorf("head %q, tail %q, cut note missing (want %d cut)", s[:8], s[len(s)-8:], cut)
	}
}

func TestTestTimesRoundTrip(t *testing.T) {
	f := filepath.Join(t.TempDir(), "times")
	in := []TestTime{{"lab TestA", 1500 * time.Millisecond}, {"example.net/m/pkg", 90 * time.Second}}
	if err := WriteTestTimes(f, in); err != nil {
		t.Fatal(err)
	}
	got, err := ReadTestTimes(f)
	if err != nil || len(got) != 2 || got[0] != in[0] || got[1] != in[1] {
		t.Fatalf("read %v, %v; want %v", got, err, in)
	}
}

// TestCheckBudget: within the budget the stream's time is reported; over
// it the check fails and lists the slowest tests, slowest first, at most
// top of them; with no budget it only reports.
func TestCheckBudget(t *testing.T) {
	times := []TestTime{{"lab TestA", time.Minute}, {"lab TestB", 5 * time.Minute}, {"pkg/c", 3 * time.Minute}, {"lab TestD", time.Second}}
	var w bytes.Buffer
	if err := CheckBudget(&w, "default", 14*time.Minute, 15*time.Minute, times, 3); err != nil || !strings.Contains(w.String(), "took 14m0s of its 15m0s budget") {
		t.Errorf("within budget: %v, %q", err, w.String())
	}
	w.Reset()
	err := CheckBudget(&w, "default", 15*time.Minute+time.Second, 15*time.Minute, times, 3)
	report := w.String()
	if err == nil {
		t.Errorf("over budget passed: %q", report)
	}
	b, c, a := strings.Index(report, "lab TestB"), strings.Index(report, "pkg/c"), strings.Index(report, "lab TestA")
	if !strings.Contains(report, "took 15m1s, over its 15m0s budget") || b < 0 || c < b || a < c || strings.Contains(report, "TestD") {
		t.Errorf("over budget report:\n%s", report)
	}
	w.Reset()
	if err := CheckBudget(&w, "long", 2*time.Hour, 0, times, 3); err != nil || w.String() != "the long stream took 2h0m0s\n" {
		t.Errorf("no budget: %v, %q", err, w.String())
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
