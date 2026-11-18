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

// Bounds on what FilterTestJSON holds: one input line, and each test's
// output kept for printing should the test fail (its first and its last
// testLogKeep bytes).
const (
	testJSONLineMax = 4 << 20
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
// without -v would have shown: a test's output only when it fails, or never
// ends (a panic, a timeout), and every line outside a test as it comes; a
// line that isn't a test event is copied as it is. It returns how long each
// test that ended took: top-level tests and their direct subtests.
func FilterTestJSON(r io.Reader, w io.Writer) ([]TestTime, error) {
	var (
		times []TestTime
		logs  = map[string]*testLog{} // by package and top-level test
	)
	flush := func(key string) error {
		l, ok := logs[key]
		if !ok {
			return nil
		}
		delete(logs, key)
		return l.writeTo(w)
	}
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, readErr := readLine(br, testJSONLineMax)
		if len(line) > 0 {
			var ev testEvent
			if line[0] != '{' || json.Unmarshal(line, &ev) != nil || ev.Action == "" {
				if _, err := w.Write(line); err != nil {
					return times, err
				}
			} else if err := filterEvent(ev, w, logs, flush, &times); err != nil {
				return times, err
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return times, readErr
		}
	}
	// Tests that never ended: their binary died under them.
	for _, k := range slices.Sorted(maps.Keys(logs)) {
		if err := flush(k); err != nil {
			return times, err
		}
	}
	return times, nil
}

func filterEvent(ev testEvent, w io.Writer, logs map[string]*testLog, flush func(string) error, times *[]TestTime) error {
	if ev.Test == "" {
		if ev.Action == "pass" || ev.Action == "fail" {
			// The package ended: what its tests never ended goes out
			// before its verdict line.
			prefix := ev.Package + "\x00"
			for k := range logs {
				if strings.HasPrefix(k, prefix) {
					if err := flush(k); err != nil {
						return err
					}
				}
			}
		}
		if ev.Output != "" {
			_, err := io.WriteString(w, ev.Output)
			return err
		}
		return nil
	}
	top, _, _ := strings.Cut(ev.Test, "/")
	key := ev.Package + "\x00" + top
	if ev.Output != "" {
		l := logs[key]
		if l == nil {
			l = &testLog{}
			logs[key] = l
		}
		l.write(ev.Output)
	}
	if ev.Action != "pass" && ev.Action != "fail" {
		return nil
	}
	if strings.Count(ev.Test, "/") <= 1 {
		*times = append(*times, TestTime{
			Name:    path.Base(ev.Package) + " " + ev.Test,
			Elapsed: time.Duration(ev.Elapsed * float64(time.Second)),
		})
	}
	if ev.Test != top {
		return nil
	}
	if ev.Action == "fail" {
		return flush(key)
	}
	delete(logs, key)
	return nil
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

// testLog is one test's output so far: its first testLogKeep bytes, and its
// last testLogKeep bytes once there are more.
type testLog struct {
	head, tail []byte
	cut        int // bytes dropped between head and tail
}

func (l *testLog) write(s string) {
	if room := testLogKeep - len(l.head); room > 0 {
		n := min(room, len(s))
		l.head = append(l.head, s[:n]...)
		s = s[n:]
	}
	l.tail = append(l.tail, s...)
	if over := len(l.tail) - testLogKeep; over > testLogKeep {
		l.cut += over
		l.tail = append(l.tail[:0], l.tail[over:]...)
	}
}

func (l *testLog) writeTo(w io.Writer) error {
	tail, cut := l.tail, l.cut
	if over := len(tail) - testLogKeep; over > 0 {
		tail, cut = tail[over:], cut+over
	}
	var b bytes.Buffer
	b.Write(l.head)
	if cut > 0 {
		fmt.Fprintf(&b, "\n... (%d bytes of this test's output cut) ...\n", cut)
	}
	b.Write(tail)
	_, err := w.Write(b.Bytes())
	return err
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

// SlowestTests is the n slowest of times, slowest first.
func SlowestTests(times []TestTime, n int) []TestTime {
	out := slices.Clone(times)
	slices.SortStableFunc(out, func(a, b TestTime) int {
		return cmp.Or(cmp.Compare(b.Elapsed, a.Elapsed), strings.Compare(a.Name, b.Name))
	})
	return out[:min(n, len(out))]
}

// CheckBudget reports to w how long a stream took and, with a budget
// (0: none), fails when it took longer, listing its top slowest tests:
// where the time went.
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
	return errors.New("over budget")
}
