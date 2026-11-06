package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"
)

// GoPackage is a package whose tests GoTest can run in a lab node.
type GoPackage struct {
	ImportPath string
	Dir        string // relative to the checkout, slash-separated
}

// ListGoPackages expands go package patterns, as seen for linux, to the
// packages that have tests.
func ListGoPackages(ctx context.Context, root string, patterns ...string) ([]GoPackage, error) {
	args := append([]string{"-C", root, "list", "-json=ImportPath,Dir,TestGoFiles,XTestGoFiles"}, patterns...)
	res, err := run(ctx, nil, []string{"GOOS=linux", "CGO_ENABLED=0"}, "go", args...)
	if err != nil {
		return nil, fmt.Errorf("lab: %w", err)
	}
	var out []GoPackage
	dec := json.NewDecoder(strings.NewReader(res.Stdout))
	for dec.More() {
		var p struct {
			ImportPath                string
			Dir                       string
			TestGoFiles, XTestGoFiles []string
		}
		if err := dec.Decode(&p); err != nil {
			return nil, err
		}
		if len(p.TestGoFiles)+len(p.XTestGoFiles) == 0 {
			continue
		}
		rel, err := filepath.Rel(root, p.Dir)
		if err != nil {
			return nil, err
		}
		out = append(out, GoPackage{ImportPath: p.ImportPath, Dir: filepath.ToSlash(rel)})
	}
	return out, nil
}

// DefaultTestTimeout bounds a package's tests in a node unless the caller
// passes its own -test.timeout.
const DefaultTestTimeout = "10m"

// GoTest compiles a package's tests for linux and runs them in the node,
// as root, with THINKPOL_LAB=1 and the package's directory as the working
// directory, so tests that need root or network namespaces run instead of
// skipping. args go to the test binary (e.g. -test.run, -test.v). Output is
// streamed to w; the error is non-nil when the tests fail.
func (n *Node) GoTest(ctx context.Context, w io.Writer, pkg GoPackage, args ...string) error {
	return n.goTest(ctx, w, pkg, nil, args)
}

// goTest is GoTest with more environment (NAME=value) for the test binary.
func (n *Node) goTest(ctx context.Context, w io.Writer, pkg GoPackage, env, args []string) error {
	t, err := dockerTarget(ctx)
	if err != nil {
		return err
	}
	name := testBinaryName(pkg)
	bin := filepath.Join(n.lab.binDir, "tests", name)
	built, err := buildTestsOnce(bin, func() (bool, error) {
		return goBuild(ctx, n.lab.root, t, bin, "test", "-c", "./"+pkg.Dir)
	})
	if err != nil || !built {
		return err // !built: no tests for linux
	}
	if !slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(strings.TrimLeft(a, "-"), "test.timeout") }) {
		args = append([]string{"-test.timeout=" + DefaultTestTimeout}, args...)
	}
	dockerArgs := []string{"exec", "-w", path.Join(SrcDir, pkg.Dir), "-e", "THINKPOL_LAB=1"}
	for _, e := range env {
		dockerArgs = append(dockerArgs, "-e", e)
	}
	dockerArgs = append(dockerArgs, n.Container, path.Join(BinDir, "tests", name))
	cmd := exec.CommandContext(ctx, "docker", append(dockerArgs, args...)...)
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: tests in %s: %w", n.Name, pkg.ImportPath, err)
	}
	return nil
}

// builtTests holds, by output path, this process's builds of packages'
// tests: each is built once per binary directory, never again under a lab
// running it.
var builtTests sync.Map // string → *testBuild

type testBuild struct {
	mu    sync.Mutex
	done  bool
	built bool // false: the package has no tests for linux
}

// buildTestsOnce runs build for the output bin until it succeeds once, and
// returns that build's result from then on. A failed build renamed nothing
// onto bin, so the next caller builds again.
func buildTestsOnce(bin string, build func() (bool, error)) (bool, error) {
	b, _ := builtTests.LoadOrStore(bin, &testBuild{})
	tb := b.(*testBuild)
	tb.mu.Lock()
	defer tb.mu.Unlock()
	if tb.done {
		return tb.built, nil
	}
	built, err := build()
	if err != nil {
		return false, err
	}
	tb.done, tb.built = true, built
	return built, nil
}

// testBinaryName is the file GoTest builds a package's tests into, under
// the lab's binary directory's tests/. The hash keeps a/b-c and a/b/c apart.
func testBinaryName(pkg GoPackage) string {
	return slug(path.Base(pkg.ImportPath), 40) + "-" + shortHash(pkg.ImportPath) + ".test"
}

// RunGoTests is GoTest for a lab test, in this node: the package's output
// goes to the test log and a failure fails the test.
func (n *Node) RunGoTests(t testing.TB, pkgPattern string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	pkgs, err := ListGoPackages(ctx, n.lab.root, pkgPattern)
	if err != nil {
		t.Fatal(err)
	}
	for _, pkg := range pkgs {
		var out syncBuffer
		err := n.GoTest(ctx, &out, pkg, append([]string{"-test.v"}, args...)...)
		t.Logf("%s:\n%s", pkg.ImportPath, out.String())
		if err != nil {
			t.Error(err)
		}
	}
}

// GoTestResult is how one package's tests went in one run.
type GoTestResult struct {
	ImportPath string
	Failed     bool
	Tests      TestTally
}

// GoTestEach runs each package's tests in a fresh lab of its own
// (GoTestTopology), up to parallel at a time, so no package sees what
// another left behind. Each package's output goes to w in one piece, in the
// order the packages finish. env (NAME=value) is added to the test
// binaries' environment. It returns each package's result, sorted by import
// path; err is for the lab itself failing. Its labs run this process's
// binaries: the caller removes them with RemoveRunBinaries once GoTestEach
// returns.
func GoTestEach(ctx context.Context, root string, pkgs []GoPackage, parallel int, w io.Writer, env []string, args ...string) (results []GoTestResult, err error) {
	checkout, err := CheckoutProject(root)
	if err != nil {
		return nil, err
	}
	var (
		mu   sync.Mutex
		errs []error
		wg   sync.WaitGroup
		sem  = make(chan struct{}, max(parallel, 1))
	)
	for _, pkg := range pkgs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var out bytes.Buffer
			fmt.Fprintf(&out, "=== lab gotest %s\n", pkg.ImportPath)
			labErr, testErr := goTestFresh(ctx, root, GoTestProject(checkout)+"-"+shortHash(pkg.ImportPath), pkg, &out, env, args)
			res := GoTestResult{ImportPath: pkg.ImportPath, Failed: testErr != nil, Tests: TallyTests(out.Bytes())}
			mu.Lock()
			defer mu.Unlock()
			if testErr != nil {
				fmt.Fprintln(&out, testErr)
			}
			if labErr != nil {
				errs = append(errs, labErr)
			}
			results = append(results, res)
			_, _ = w.Write(out.Bytes())
		}()
	}
	wg.Wait()
	slices.SortFunc(results, func(a, b GoTestResult) int { return strings.Compare(a.ImportPath, b.ImportPath) })
	return results, errors.Join(errs...)
}

func goTestFresh(ctx context.Context, root, project string, pkg GoPackage, w io.Writer, env, args []string) (labErr, testErr error) {
	l, err := up(ctx, root, project, GoTestTopology(), "", runInputs)
	if l != nil {
		defer func() {
			if err := l.Down(context.WithoutCancel(ctx)); err != nil && labErr == nil {
				labErr = err
			}
		}()
	}
	if err != nil {
		return err, nil
	}
	return nil, l.Node("gotest").goTest(ctx, w, pkg, env, args)
}

// GoTestTopology is the lab GoTest runs packages in when no topology is
// given: one node on one network, no default route. Tests build whatever
// they need (namespaces, veths, TUNs) inside it.
func GoTestTopology() Topology {
	return Topology{
		Networks: []Network{{Name: "lab"}},
		Nodes:    []NodeSpec{{Name: "gotest", Networks: []string{"lab"}}},
	}
}

// ListLabTaggedPackages expands go package patterns, as seen for this
// machine, to the packages that have test files behind the lab build tag:
// lab tests, which start labs from the host and need Docker there, not in
// a node.
func ListLabTaggedPackages(ctx context.Context, root string, patterns ...string) ([]GoPackage, error) {
	untagged, err := listTestFiles(ctx, root, nil, patterns)
	if err != nil {
		return nil, err
	}
	tagged, err := listTestFiles(ctx, root, []string{"-tags=lab"}, patterns)
	if err != nil {
		return nil, err
	}
	var out []GoPackage
	for _, p := range tagged {
		if p.testFiles <= untagged[p.ImportPath].testFiles {
			continue
		}
		out = append(out, p.GoPackage)
	}
	slices.SortFunc(out, func(a, b GoPackage) int { return strings.Compare(a.ImportPath, b.ImportPath) })
	return out, nil
}

type listedPackage struct {
	GoPackage
	testFiles int
}

func listTestFiles(ctx context.Context, root string, flags, patterns []string) (map[string]listedPackage, error) {
	args := append(append([]string{"-C", root, "list", "-json=ImportPath,Dir,TestGoFiles,XTestGoFiles"}, flags...), patterns...)
	res, err := run(ctx, nil, nil, "go", args...)
	if err != nil {
		return nil, fmt.Errorf("lab: %w", err)
	}
	out := map[string]listedPackage{}
	dec := json.NewDecoder(strings.NewReader(res.Stdout))
	for dec.More() {
		var p struct {
			ImportPath                string
			Dir                       string
			TestGoFiles, XTestGoFiles []string
		}
		if err := dec.Decode(&p); err != nil {
			return nil, err
		}
		rel, err := filepath.Rel(root, p.Dir)
		if err != nil {
			return nil, err
		}
		out[p.ImportPath] = listedPackage{
			GoPackage: GoPackage{ImportPath: p.ImportPath, Dir: filepath.ToSlash(rel)},
			testFiles: len(p.TestGoFiles) + len(p.XTestGoFiles),
		}
	}
	return out, nil
}

// DefaultLabTestTimeout bounds a package's lab tests (GoTestLabTagged)
// unless the caller passes its own -test.timeout; it matches make lab-test's
// LAB_TIMEOUT.
const DefaultLabTestTimeout = "20m"

// GoTestLabTagged runs a package's tests on this machine with the lab build
// tag, as make lab-test runs ./lab/...: its lab tests start their own labs
// and run in-node tests there, and its tests without the tag run too. args
// are test binary flags (-test.v, -test.run, ...); env (NAME=value) is
// added to the environment. Output is streamed to w; the error is non-nil
// when the tests fail.
func GoTestLabTagged(ctx context.Context, root string, pkg GoPackage, w io.Writer, env []string, args ...string) (GoTestResult, error) {
	if !slices.ContainsFunc(args, func(a string) bool { return strings.HasPrefix(strings.TrimLeft(a, "-"), "test.timeout") }) {
		args = append([]string{"-test.timeout=" + DefaultLabTestTimeout}, args...)
	}
	// -count=1 before the package: a later -test.count from args wins, and
	// either way the result is never served from the test cache.
	cmd := exec.CommandContext(ctx, "go", append([]string{"-C", root, "test", "-tags=lab", "-count=1", "./" + pkg.Dir}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	var out syncBuffer
	cmd.Stdout = io.MultiWriter(w, &out)
	cmd.Stderr = cmd.Stdout
	err := cmd.Run()
	res := GoTestResult{ImportPath: pkg.ImportPath, Failed: err != nil, Tests: TallyTests([]byte(out.String()))}
	if err != nil {
		return res, fmt.Errorf("lab tests in %s: %w", pkg.ImportPath, err)
	}
	return res, nil
}

// TestTally counts a verbose (-test.v) test run's top-level tests by
// outcome. Subtests, and test output nested in a lab test's log (indented),
// don't count.
type TestTally struct {
	Passed, Failed, Skipped int
}

// TallyTests tallies the "--- PASS/FAIL/SKIP: " lines that start a line in
// a verbose test run's output.
func TallyTests(out []byte) TestTally {
	var t TestTally
	for line := range strings.Lines(string(out)) {
		switch {
		case strings.HasPrefix(line, "--- PASS: "):
			t.Passed++
		case strings.HasPrefix(line, "--- FAIL: "):
			t.Failed++
		case strings.HasPrefix(line, "--- SKIP: "):
			t.Skipped++
		}
	}
	return t
}

// Ran is how many tests ran, skipped ones included.
func (t TestTally) Ran() int { return t.Passed + t.Failed + t.Skipped }

// OnlySkipped returns, sorted, the packages in which at least one test ran
// and every test that ran, over all of a package's results, skipped.
func OnlySkipped(results []GoTestResult) []string {
	byPkg := map[string]TestTally{}
	for _, r := range results {
		t := byPkg[r.ImportPath]
		t.Passed += r.Tests.Passed
		t.Failed += r.Tests.Failed
		t.Skipped += r.Tests.Skipped
		byPkg[r.ImportPath] = t
	}
	var out []string
	for pkg, t := range byPkg {
		if t.Skipped > 0 && t.Passed+t.Failed == 0 {
			out = append(out, pkg)
		}
	}
	slices.Sort(out)
	return out
}
