package lab

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path"
	"path/filepath"
	"slices"
	"sort"
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
	once  sync.Once
	built bool // false: the package has no tests for linux
	err   error
}

// buildTestsOnce runs build for the output bin the first time it is asked
// for, and returns that build's result every time.
func buildTestsOnce(bin string, build func() (bool, error)) (bool, error) {
	b, _ := builtTests.LoadOrStore(bin, &testBuild{})
	tb := b.(*testBuild)
	tb.once.Do(func() { tb.built, tb.err = build() })
	return tb.built, tb.err
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

// GoTestEach runs each package's tests in a fresh lab of its own
// (GoTestTopology), up to parallel at a time, so no package sees what
// another left behind. Each package's output goes to w in one piece, in the
// order the packages finish. env (NAME=value) is added to the test
// binaries' environment. It returns the packages that failed; err is for
// the lab itself failing.
func GoTestEach(ctx context.Context, root string, pkgs []GoPackage, parallel int, w io.Writer, env []string, args ...string) (failed []string, err error) {
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
			mu.Lock()
			defer mu.Unlock()
			if testErr != nil {
				fmt.Fprintln(&out, testErr)
				failed = append(failed, pkg.ImportPath)
			}
			if labErr != nil {
				errs = append(errs, labErr)
			}
			_, _ = w.Write(out.Bytes())
		}()
	}
	wg.Wait()
	sort.Strings(failed)
	return failed, errors.Join(errs...)
}

func goTestFresh(ctx context.Context, root, project string, pkg GoPackage, w io.Writer, env, args []string) (labErr, testErr error) {
	l, err := Up(ctx, root, project, GoTestTopology())
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
