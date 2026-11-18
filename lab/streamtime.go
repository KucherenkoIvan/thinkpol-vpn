package lab

import (
	"bufio"
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"
)

// TestTime is how long one test, or one package of the node phase, took.
type TestTime struct {
	Name    string
	Elapsed time.Duration
}

// Bounds on what FilterTestJSON holds: one input line; each test's output
// held in memory before it spills to a temporary file; and what is printed
// of a failed test's output, its first and its last testLogKeep bytes.
const (
	testJSONLineMax = 4 << 20
	testLogMem      = 256 << 10
	testLogKeep     = 1 << 20
)

// testEvent is one line of go test -json (go doc test2json).
type testEvent struct {
	Action  string
	Package string
	Test    string
	Output  string
	Elapsed float64
}

// FilterTestJSON reads go test -json from r and writes to w what go test
// without -v would have shown, or with verbose what go test -v shows. A
// line outside a test goes out as it comes, and a line that isn't a test
// event is copied as it is. Without verbose, a test's output goes out only
// when it fails: its own lines and those of its subtests that failed, not
// of those that passed, without the === RUN, PAUSE, CONT and NAME lines,
// and cut to its first and last testLogKeep bytes. A test that never ended
// (a panic, a timeout's goroutine dump) goes out whole, before its
// package's verdict. It returns how long each test that ended took:
// top-level tests and their direct subtests.
func FilterTestJSON(r io.Reader, w io.Writer, verbose bool) ([]TestTime, error) {
	f := testFilter{w: w, verbose: verbose, logs: map[string]*testLog{}}
	defer f.close()
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, readErr := readLine(br, testJSONLineMax)
		if len(line) > 0 {
			var ev testEvent
			if line[0] != '{' || json.Unmarshal(line, &ev) != nil || ev.Action == "" {
				if _, err := w.Write(line); err != nil {
					return f.times, err
				}
			} else if err := f.event(ev); err != nil {
				return f.times, err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return f.times, readErr
		}
	}
	// Tests that never ended: their binary died under them.
	return f.times, f.flushUnended("")
}

type testFilter struct {
	w       io.Writer
	verbose bool
	logs    map[string]*testLog // by package and full test name
	times   []TestTime
}

func testKey(pkg, test string) string { return pkg + "\x00" + test }

func (f *testFilter) event(ev testEvent) error {
	if ev.Test == "" {
		if !f.verbose && (ev.Output != "" || ev.Action == "pass" || ev.Action == "fail") {
			// Outside a test, output comes before the first test starts or
			// once its binary is done (its verdict line, before the
			// package's end): what its tests never ended goes out first.
			if err := f.flushUnended(ev.Package); err != nil {
				return err
			}
		}
		_, err := io.WriteString(f.w, ev.Output)
		return err
	}
	ended := ev.Action == "pass" || ev.Action == "fail"
	if ended && strings.Count(ev.Test, "/") <= 1 {
		f.times = append(f.times, TestTime{
			Name:    path.Base(ev.Package) + " " + ev.Test,
			Elapsed: time.Duration(ev.Elapsed * float64(time.Second)),
		})
	}
	if f.verbose {
		_, err := io.WriteString(f.w, ev.Output)
		return err
	}
	key := testKey(ev.Package, ev.Test)
	if ev.Output != "" && !isFraming(ev.Output) {
		l := f.logs[key]
		if l == nil {
			l = &testLog{}
			f.logs[key] = l
		}
		if err := l.write([]byte(ev.Output)); err != nil {
			return err
		}
	}
	switch ev.Action {
	case "pass", "skip":
		f.drop(key)
	case "fail":
		l := f.logs[key]
		if l == nil {
			return nil
		}
		delete(f.logs, key)
		defer l.close()
		parent, _, sub := cutLast(ev.Test, "/")
		if !sub {
			return l.writeTo(f.w, false)
		}
		pk := testKey(ev.Package, parent)
		p := f.logs[pk]
		if p == nil {
			p = &testLog{}
			f.logs[pk] = p
		}
		return l.writeTo(p, true)
	}
	return nil
}

func (f *testFilter) drop(key string) {
	if l, ok := f.logs[key]; ok {
		l.close()
		delete(f.logs, key)
	}
}

// flushUnended writes, whole and in name order, the output of the tests of
// pkg ("": every package) that haven't ended.
func (f *testFilter) flushUnended(pkg string) error {
	prefix := ""
	if pkg != "" {
		prefix = testKey(pkg, "")
	}
	for _, k := range slices.Sorted(maps.Keys(f.logs)) {
		if !strings.HasPrefix(k, prefix) {
			continue
		}
		l := f.logs[k]
		delete(f.logs, k)
		err := l.writeTo(f.w, true)
		l.close()
		if err != nil {
			return err
		}
	}
	return nil
}

func (f *testFilter) close() {
	for k := range f.logs {
		f.drop(k)
	}
}

// isFraming says whether a line is the testing package's framing that go
// test without -v doesn't print.
func isFraming(s string) bool {
	for _, p := range []string{"=== RUN ", "=== PAUSE ", "=== CONT ", "=== NAME "} {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

func cutLast(s, sep string) (before, after string, found bool) {
	if i := strings.LastIndex(s, sep); i >= 0 {
		return s[:i], s[i+len(sep):], true
	}
	return s, "", false
}

// readLine reads one line, its newline included, keeping at most max
// bytes of it: the rest of a longer line is read and dropped.
func readLine(br *bufio.Reader, max int) ([]byte, error) {
	var line []byte
	cut := false
	for {
		chunk, err := br.ReadSlice('\n')
		if room := max - len(line); len(chunk) > room {
			chunk, cut = chunk[:room], true
		}
		line = append(line, chunk...)
		if err == bufio.ErrBufferFull {
			continue
		}
		if cut {
			line = append(line, '\n')
		}
		return line, err
	}
}

// testLog is one test's output so far, whole: in memory up to testLogMem
// bytes, then in a temporary file.
type testLog struct {
	mem  []byte
	file *os.File
	size int64
}

func (l *testLog) Write(b []byte) (int, error) {
	if err := l.write(b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (l *testLog) write(b []byte) error {
	if l.file == nil && len(l.mem)+len(b) > testLogMem {
		f, err := os.CreateTemp("", "labctl-testlog-*")
		if err != nil {
			return err
		}
		l.file = f
		if _, err := f.Write(l.mem); err != nil {
			return err
		}
		l.mem = nil
	}
	l.size += int64(len(b))
	if l.file == nil {
		l.mem = append(l.mem, b...)
		return nil
	}
	_, err := l.file.Write(b)
	return err
}

// writeTo writes the output to w: whole, or its first and its last
// testLogKeep bytes with how much was cut between them.
func (l *testLog) writeTo(w io.Writer, whole bool) error {
	var r io.ReaderAt = bytes.NewReader(l.mem)
	if l.file != nil {
		r = l.file
	}
	if whole || l.size <= 2*testLogKeep {
		_, err := io.Copy(w, io.NewSectionReader(r, 0, l.size))
		return err
	}
	if _, err := io.Copy(w, io.NewSectionReader(r, 0, testLogKeep)); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\n... (%d bytes of this test's output cut) ...\n", l.size-2*testLogKeep); err != nil {
		return err
	}
	_, err := io.Copy(w, io.NewSectionReader(r, l.size-testLogKeep, testLogKeep))
	return err
}

func (l *testLog) close() {
	if l.file != nil {
		_ = l.file.Close()
		_ = os.Remove(l.file.Name())
		l.file = nil
	}
}

// WriteTestTimes writes times to a file, one "seconds<TAB>name" line each.
func WriteTestTimes(name string, times []TestTime) error {
	var b strings.Builder
	for _, t := range times {
		fmt.Fprintf(&b, "%.3f\t%s\n", t.Elapsed.Seconds(), t.Name)
	}
	return os.WriteFile(name, []byte(b.String()), 0o644)
}

// ReadTestTimes reads a file WriteTestTimes wrote.
func ReadTestTimes(name string) ([]TestTime, error) {
	b, err := os.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var times []TestTime
	for line := range strings.Lines(string(b)) {
		secs, test, ok := strings.Cut(strings.TrimSuffix(line, "\n"), "\t")
		s, err := strconv.ParseFloat(secs, 64)
		if !ok || err != nil {
			return nil, fmt.Errorf("%s: bad line %q", name, line)
		}
		times = append(times, TestTime{Name: test, Elapsed: time.Duration(s * float64(time.Second))})
	}
	return times, nil
}

// SlowestTests is the n slowest of times, slowest first. A test whose
// subtests are timed too is left out: its time is theirs, and its line
// would push one of them off the list.
func SlowestTests(times []TestTime, n int) []TestTime {
	parents := map[string]bool{}
	for _, t := range times {
		if parent, _, ok := cutLast(t.Name, "/"); ok {
			parents[parent] = true
		}
	}
	var out []TestTime
	for _, t := range times {
		if !parents[t.Name] {
			out = append(out, t)
		}
	}
	slices.SortStableFunc(out, func(a, b TestTime) int {
		return cmp.Or(cmp.Compare(b.Elapsed, a.Elapsed), strings.Compare(a.Name, b.Name))
	})
	return out[:min(n, len(out))]
}

// OverBudgetError is CheckBudget's failure: the stream took Took, over its
// Budget.
type OverBudgetError struct{ Took, Budget time.Duration }

func (e *OverBudgetError) Error() string {
	return fmt.Sprintf("over budget: %v > %v", e.Took, e.Budget)
}

// CheckBudget reports to w how long a stream took and, with a budget
// (0: none), fails with an *OverBudgetError when it took longer, listing
// its top slowest tests: where the time went.
func CheckBudget(w io.Writer, stream string, took, budget time.Duration, times []TestTime, top int) error {
	took = took.Round(time.Second)
	if budget <= 0 {
		_, err := fmt.Fprintf(w, "the %s stream took %v\n", stream, took)
		return err
	}
	if took <= budget {
		_, err := fmt.Fprintf(w, "the %s stream took %v of its %v budget\n", stream, took, budget)
		return err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "the %s stream took %v, over its %v budget (LAB_BUDGET: wall time from the stream's start, lab setup included); its slowest tests:\n", stream, took, budget)
	for _, t := range SlowestTests(times, top) {
		fmt.Fprintf(&b, "  %10v  %s\n", t.Elapsed.Round(100*time.Millisecond), t.Name)
	}
	if _, err := io.WriteString(w, b.String()); err != nil {
		return err
	}
	return &OverBudgetError{Took: took, Budget: budget}
}

// ParseBudget parses a stream's time budget (LAB_BUDGET): a Go duration,
// 0 for none. Empty or negative is an error: neither may turn the check
// off unseen.
func ParseBudget(s string) (time.Duration, error) {
	if s == "" {
		return 0, errors.New("empty budget: want a Go duration, 0 for none")
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, err
	}
	if d < 0 {
		return 0, fmt.Errorf("negative budget %v: want a Go duration, 0 for none", d)
	}
	return d, nil
}
