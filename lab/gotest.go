package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"path"
	"path/filepath"
	"strings"
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

// GoTest compiles a package's tests for linux and runs them in the node,
// as root, with THINKPOL_LAB=1 and the package's directory as the working
// directory, so tests that need root or network namespaces run instead of
// skipping. args go to the test binary (e.g. -test.run, -test.v). Output is
// streamed to w; the error is non-nil when the tests fail.
func (n *Node) GoTest(ctx context.Context, w io.Writer, pkg GoPackage, args ...string) error {
	arch, err := dockerArch(ctx)
	if err != nil {
		return err
	}
	name := slug(pkg.ImportPath, 200) + ".test"
	built, err := buildTestBinary(ctx, n.lab.root, arch, "./"+pkg.Dir, filepath.Join(n.lab.root, "lab", "bin", "tests", name))
	if err != nil {
		return err
	}
	if !built {
		return nil
	}
	cmd := exec.CommandContext(ctx, "docker", append([]string{
		"exec", "-w", path.Join(SrcDir, pkg.Dir), "-e", "THINKPOL_LAB=1", n.Container,
		path.Join(BinDir, "tests", name),
	}, args...)...)
	cmd.Stdout, cmd.Stderr = w, w
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: tests in %s: %w", n.Name, pkg.ImportPath, err)
	}
	return nil
}

// RunGoTests is GoTest for a lab test: the package's output goes to the test
// log and a failure fails the test.
func (n *Node) RunGoTests(t testing.TB, pkgPattern string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
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

// GoTestTopology is the lab GoTest runs packages in when no topology is
// given: one node on one network, no default route. Tests build whatever
// they need (namespaces, veths, TUNs) inside it.
func GoTestTopology() Topology {
	return Topology{
		Networks: []Network{{Name: "lab"}},
		Nodes:    []NodeSpec{{Name: "gotest", Networks: []string{"lab"}}},
	}
}

// GoTestProject is the Compose project labctl gotest uses.
func GoTestProject(checkout string) string { return checkout + "-gotest" }
