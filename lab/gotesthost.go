package lab

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"
)

// HostTestsFile marks a package whose tests need no lab node: no test of
// it reads THINKPOL_LAB, needs root, a network namespace or anything else
// only a node has. On a Linux machine GoTestOnHost runs such a package as
// plain go test, cached by go's own test cache, instead of starting a lab
// for it; elsewhere it still runs in a node, where its Linux files build.
// The file holds nothing but the package clause and why the package needs
// no node.
const HostTestsFile = "hosttests_test.go"

// hostOutputLimit bounds one host package's output held until it ends.
const hostOutputLimit = 8 << 20

// GoTestOnHost runs packages' tests on this machine with one go test
// -json, as a user and without THINKPOL_LAB, so a test that would need
// the lab skips (and fails the package here) instead of running. args are
// test binary flags (-test.v, -test.run, ...), which go test takes too;
// env (NAME=value) is added to the environment. Each package's output goes
// to w in one piece, as it ends. A package any of whose tests skipped
// fails: its tests needed something only a node has, and HostTestsFile
// shouldn't be in it. The error is for go test not running at all, or
// ending with packages unreported.
func GoTestOnHost(ctx context.Context, root string, pkgs []GoPackage, w io.Writer, env []string, args ...string) ([]GoTestResult, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}
	goArgs := append([]string{"-C", root, "test", "-json"}, args...)
	byPath := map[string]GoPackage{}
	for _, p := range pkgs {
		goArgs = append(goArgs, "./"+p.Dir)
		byPath[p.ImportPath] = p
	}
	cmd := exec.CommandContext(ctx, "go", goArgs...)
	cmd.Env = append(slices.DeleteFunc(os.Environ(), func(e string) bool { return strings.HasPrefix(e, "THINKPOL_LAB=") }), env...)
	killGroupOnCancel(cmd)
	cmd.WaitDelay = labTestWaitDelay
	cmd.Stderr = w
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("lab: go test on the host: %w", err)
	}
	h := hostRun{w: w, wanted: byPath, outs: map[string]*hostOutput{}}
	readErr := h.read(stdout)
	waitErr := cmd.Wait()
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

type hostOutput struct {
	b   strings.Builder
	cut int // bytes not held: over hostOutputLimit
}

func (o *hostOutput) add(s string) {
	if o.b.Len()+len(s) > hostOutputLimit {
		o.cut += len(s)
		return
	}
	o.b.WriteString(s)
}

type hostRun struct {
	w       io.Writer
	wanted  map[string]GoPackage
	outs    map[string]*hostOutput
	results []GoTestResult
}

func (h *hostRun) out(pkg string) *hostOutput {
	o := h.outs[pkg]
	if o == nil {
		o = &hostOutput{}
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
			h.out(pkg).add(e.Output)
		} else {
			_, _ = io.WriteString(h.w, e.Output)
		}
	case e.Package == "" || e.Action == "build-fail":
	case e.Action == "output":
		h.out(e.Package).add(e.Output)
	case e.Test == "" && (e.Action == "pass" || e.Action == "fail" || e.Action == "skip"):
		h.end(e)
	}
}

// end reports a package that ended.
func (h *hostRun) end(e hostEvent) {
	o := h.out(e.Package)
	delete(h.outs, e.Package)
	out := o.b.String()
	res := GoTestResult{ImportPath: e.Package, Failed: e.Action == "fail", Tests: TallyTests([]byte(out))}
	res.Cached = strings.Contains(out, "\t(cached)")
	if !res.Cached {
		res.Elapsed = time.Duration(e.Elapsed * float64(time.Second))
	}
	var b strings.Builder
	b.WriteString("=== lab gotest (on the host) " + e.Package)
	if res.Cached {
		b.WriteString(" (cached)")
	}
	b.WriteString("\n" + out)
	if o.cut > 0 {
		fmt.Fprintf(&b, "lab: %d bytes of %s's output cut\n", o.cut, e.Package)
	}
	if res.Tests.Skipped > 0 {
		res.Failed = true
		fmt.Fprintf(&b, "lab gotest %s: %d tests skipped on the host: a test here needs a lab node (THINKPOL_LAB, root, a namespace), so the package can't have %s\n", e.Package, res.Tests.Skipped, HostTestsFile)
	}
	if !res.Cached {
		fmt.Fprintf(&b, "lab gotest %s: took %v (on the host)\n", e.Package, res.Elapsed.Round(100*time.Millisecond))
	}
	_, _ = io.WriteString(h.w, b.String())
	h.results = append(h.results, res)
}
