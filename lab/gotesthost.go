package lab

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"
)

// HostTestsFile marks a package whose tests need no lab node: no test of
// it reads THINKPOL_LAB, needs root, a network namespace or anything else
// only a node has. On a Linux machine, as a user, GoTestOnHost runs such a
// package as plain go test, cached by go's own test cache, instead of
// starting a lab for it; elsewhere, and as root, it still runs in a node.
// The file holds nothing but the package clause and why the package needs
// no node.
const HostTestsFile = "hosttests_test.go"

// GoTestOnHost runs packages' tests on this machine with one go test
// -json, without THINKPOL_LAB, so a test that would need the lab skips
// (and fails the package here) instead of running. builds packages compile
// and run at once (go test -p), as in a node's run with CGO_ENABLED=0.
// args are test binary flags (-test.v, -test.run, ...), which go test
// takes too; env (NAME=value) is added to the environment. Each package's
// output goes to w in one piece, as it ends: what go test would print
// (with -test.v, what go test -v would), cut to its first and last MiB. A
// package any of whose tests skipped fails: its tests needed something
// only a node has, and HostTestsFile shouldn't be in it. The error is for
// go test not running at all, or ending with packages unreported. The
// caller runs it only as a user: as root, a test would act on the host's
// own namespaces.
func GoTestOnHost(ctx context.Context, root string, pkgs []GoPackage, builds int, w io.Writer, env []string, args ...string) ([]GoTestResult, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	byPath := map[string]GoPackage{}
	for _, p := range pkgs {
		byPath[p.ImportPath] = p
	}
	cmd := hostGoTestCommand(ctx, root, pkgs, builds, env, args)
	cmd.Stderr = w
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("lab: go test on the host: %w", err)
	}
	h := newHostRun(w, byPath, testVerbose(args))
	readErr := h.read(stdout)
	waitErr := cmd.Wait()
	h.flushUnreported()
	var missing []string
	for path := range byPath {
		if !slices.ContainsFunc(h.results, func(r GoTestResult) bool { return r.ImportPath == path }) {
			missing = append(missing, path)
			h.results = append(h.results, GoTestResult{ImportPath: path, Failed: true})
		}
	}
	slices.SortFunc(h.results, func(a, b GoTestResult) int { return strings.Compare(a.ImportPath, b.ImportPath) })
	if len(missing) > 0 {
		slices.Sort(missing)
		return h.results, errors.Join(readErr, fmt.Errorf("lab: go test on the host ended (%v) without a result for %s", waitErr, strings.Join(missing, " ")))
	}
	return h.results, readErr
}

// hostGoTestCommand is GoTestOnHost's go test.
func hostGoTestCommand(ctx context.Context, root string, pkgs []GoPackage, builds int, env, args []string) *exec.Cmd {
	goArgs := append([]string{"-C", root, "test", "-json", "-p", strconv.Itoa(max(builds, 1))}, args...)
	for _, p := range pkgs {
		goArgs = append(goArgs, "./"+p.Dir)
	}
	cmd := exec.CommandContext(ctx, "go", goArgs...)
	cmd.Env = slices.DeleteFunc(os.Environ(), func(e string) bool {
		return strings.HasPrefix(e, "THINKPOL_LAB=") || strings.HasPrefix(e, "CGO_ENABLED=")
	})
	cmd.Env = append(append(cmd.Env, "CGO_ENABLED=0"), env...)
	killGroupOnCancel(cmd)
	cmd.WaitDelay = labTestWaitDelay
	return cmd
}

// testVerbose says whether test binary flags ask for -test.v.
func testVerbose(args []string) bool {
	for _, a := range args {
		if v, ok := strings.CutPrefix(a, "-test.v"); ok && (v == "" || v == "=true") {
			return true
		}
	}
	return false
}

// hostEvent is one line of go test -json (go doc test2json), build events
// included.
type hostEvent struct {
	Action     string
	Package    string
	ImportPath string // build-output, build-fail
	Test       string
	Output     string
	Elapsed    float64
}

// hostOutput is one package's output so far, filtered as FilterTestJSON
// filters a stream's: in memory, then in a temporary file.
type hostOutput struct {
	log    testLog
	filter testFilter // writes to log
	err    error      // the first error writing log
	tally  TestTally
	cached bool // go test said "(cached)" on the package's verdict line
}

func (o *hostOutput) write(s string) {
	if o.err == nil {
		o.err = o.log.write([]byte(s))
	}
}

func (o *hostOutput) event(e hostEvent) {
	if o.err == nil {
		o.err = o.filter.event(testEvent{Action: e.Action, Package: e.Package, Test: e.Test, Output: e.Output, Elapsed: e.Elapsed})
	}
}

func (o *hostOutput) close() {
	o.filter.close()
	o.log.close()
}

type hostRun struct {
	w       io.Writer
	wanted  map[string]GoPackage
	verbose bool
	outs    map[string]*hostOutput
	results []GoTestResult
}

func newHostRun(w io.Writer, wanted map[string]GoPackage, verbose bool) *hostRun {
	return &hostRun{w: w, wanted: wanted, verbose: verbose, outs: map[string]*hostOutput{}}
}

func (h *hostRun) out(pkg string) *hostOutput {
	o := h.outs[pkg]
	if o == nil {
		o = &hostOutput{}
		o.log.what = pkg + "'s output"
		o.filter = testFilter{w: &o.log, verbose: h.verbose, logs: map[string]*testLog{}, reported: map[string]bool{}}
		h.outs[pkg] = o
	}
	return o
}

func (h *hostRun) read(r io.Reader) error {
	br := bufio.NewReaderSize(r, 64<<10)
	for {
		line, err := readLine(br, testJSONLineMax)
		if len(line) > 0 {
			h.line(line)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (h *hostRun) line(line []byte) {
	var e hostEvent
	if len(line) == 0 || line[0] != '{' || json.Unmarshal(line, &e) != nil {
		_, _ = h.w.Write(line)
		return
	}
	switch {
	case e.Action == "build-output":
		// "pkg [pkg.test]" builds pkg's tests.
		pkg, _, _ := strings.Cut(e.ImportPath, " ")
		if _, ok := h.wanted[pkg]; ok {
			h.out(pkg).write(e.Output)
		} else {
			_, _ = io.WriteString(h.w, e.Output)
		}
	case e.Package == "" || e.Action == "build-fail":
	case e.Test == "" && (e.Action == "pass" || e.Action == "fail" || e.Action == "skip"):
		h.end(e)
	default:
		o := h.out(e.Package)
		if e.Test == "" && e.Action == "output" && strings.HasPrefix(e.Output, "ok ") && strings.HasSuffix(strings.TrimSpace(e.Output), "(cached)") {
			o.cached = true
		}
		// From the events, not the output's "--- " lines: go test -json
		// prints a subtest's unindented.
		if e.Action == "pass" || e.Action == "fail" || e.Action == "skip" {
			if !strings.Contains(e.Test, "/") {
				o.count(e.Action)
			}
		}
		o.event(e)
	}
}

func (o *hostOutput) count(action string) {
	switch action {
	case "pass":
		o.tally.Passed++
	case "fail":
		o.tally.Failed++
	case "skip":
		o.tally.Skipped++
	}
}

// end reports a package that ended.
func (h *hostRun) end(e hostEvent) {
	o := h.out(e.Package)
	delete(h.outs, e.Package)
	defer o.close()
	o.event(e) // its verdict, after what its tests never ended
	res := GoTestResult{ImportPath: e.Package, Failed: e.Action == "fail", Tests: o.tally, Cached: o.cached}
	if !res.Cached {
		res.Elapsed = time.Duration(e.Elapsed * float64(time.Second))
	}
	var b bytes.Buffer
	b.WriteString("=== lab gotest (on the host) " + e.Package)
	if res.Cached {
		b.WriteString(" (cached)")
	}
	b.WriteByte('\n')
	h.writeLog(&b, e.Package, o)
	if res.Tests.Skipped > 0 {
		res.Failed = true
		fmt.Fprintf(&b, "lab gotest %s: %d tests skipped on the host: a test here needs a lab node (THINKPOL_LAB, root, a namespace), so the package can't have %s\n", e.Package, res.Tests.Skipped, HostTestsFile)
	}
	if !res.Cached {
		fmt.Fprintf(&b, "lab gotest %s: took %v (on the host)\n", e.Package, res.Elapsed.Round(100*time.Millisecond))
	}
	_, _ = h.w.Write(b.Bytes())
	h.results = append(h.results, res)
}

// writeLog writes a package's output, cut to its first and last
// testLogKeep bytes.
func (h *hostRun) writeLog(b *bytes.Buffer, pkg string, o *hostOutput) {
	if o.err == nil {
		o.err = o.log.writeTo(b, false)
	}
	if o.err != nil {
		fmt.Fprintf(b, "lab: %s's output: %v\n", pkg, o.err)
	}
}

// flushUnreported writes the output of packages go test never gave a
// verdict for (it was killed, or crashed), each with its tests that never
// ended whole.
func (h *hostRun) flushUnreported() {
	for _, pkg := range slices.Sorted(maps.Keys(h.outs)) {
		o := h.outs[pkg]
		delete(h.outs, pkg)
		if o.err == nil {
			o.err = o.filter.flushUnended("")
		}
		var b bytes.Buffer
		b.WriteString("=== lab gotest (on the host) " + pkg + " (no verdict)\n")
		h.writeLog(&b, pkg, o)
		_, _ = h.w.Write(b.Bytes())
		o.close()
	}
}
