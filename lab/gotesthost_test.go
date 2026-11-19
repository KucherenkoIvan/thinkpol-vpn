package lab

import (
	"context"
	"maps"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// needsNode matches what a test that needs a lab node uses: the lab's
// variable, root, a network namespace (nsthread, netns, unshare, setns).
var needsNode = regexp.MustCompile(`THINKPOL_LAB|Geteuid|Getuid|Unshare|Setns|CLONE_NEW|nsthread|netns`)

// TestNodelessPackagesNeedNoNode: no package with HostTestsFile has a test
// file, or uses a test helper package (one named ...test in this module),
// that reads THINKPOL_LAB, asks for root or enters a network namespace:
// its tests would skip or fail on the host, or, worse, prove less there
// than in a node. Every package marked is listed, so a mark can't go
// unchecked.
func TestNodelessPackagesNeedNoNode(t *testing.T) {
	needGoTool(t)
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := ListGoPackages(t.Context(), root, "./...")
	if err != nil {
		t.Fatal(err)
	}
	var marked []string
	for _, p := range pkgs {
		if !p.NeedsNoNode {
			continue
		}
		marked = append(marked, p.ImportPath)
		files, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(p.Dir), "*_test.go"))
		if err != nil {
			t.Fatal(err)
		}
		helpers, err := testHelperDirs(t.Context(), root, p)
		if err != nil {
			t.Fatal(err)
		}
		for _, dir := range helpers {
			more, err := filepath.Glob(filepath.Join(dir, "*.go"))
			if err != nil {
				t.Fatal(err)
			}
			files = append(files, more...)
		}
		for _, f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if m := needsNode.Find(b); m != nil {
				rel, _ := filepath.Rel(root, f)
				t.Errorf("%s has %s, but %s uses %q: its tests need a node", p.ImportPath, HostTestsFile, rel, m)
			}
		}
	}
	if len(marked) == 0 {
		t.Fatalf("no package has %s: the check checks nothing", HostTestsFile)
	}
	t.Logf("packages whose tests run on the host: %s", strings.Join(marked, " "))
}

// testHelperDirs lists the directories of the test helper packages of
// this module (named ...test) that the package's tests build with.
func testHelperDirs(ctx context.Context, root string, p GoPackage) ([]string, error) {
	res, err := run(ctx, nil, []string{"GOOS=linux", "CGO_ENABLED=0"}, "go", "-C", root, "list", "-deps", "-test", "-f", "{{if .Module}}{{if .Module.Main}}{{.ImportPath}}\t{{.Dir}}{{end}}{{end}}", "./"+p.Dir)
	if err != nil {
		return nil, err
	}
	var dirs []string
	for line := range strings.Lines(res.Stdout) {
		pkg, dir, ok := strings.Cut(strings.TrimSpace(line), "\t")
		// "x [y.test]" is x built for y's tests. y's external tests
		// (y_test) and their main package (y.test) are in y's directory:
		// not helpers.
		pkg, _, _ = strings.Cut(pkg, " ")
		base := path.Base(pkg)
		helper := strings.HasSuffix(base, "test") && !strings.ContainsAny(base, "._")
		if ok && helper && !slices.Contains(dirs, dir) {
			dirs = append(dirs, dir)
		}
	}
	return dirs, nil
}

// TestListGoPackagesFindsTheHostTestsMark: a package with HostTestsFile,
// in its own package or as an external test, needs no node; one without
// it does.
func TestListGoPackagesFindsTheHostTestsMark(t *testing.T) {
	needGoTool(t)
	isolateGoEnv(t)
	root := writeModule(t, map[string]string{
		"host/host_test.go":      pkgFile(passTest, "host"),
		"host/" + HostTestsFile:  "package host\n",
		"xhost/x.go":             "package xhost\n",
		"xhost/x_test.go":        pkgFile(passTest, "xhost_test"),
		"xhost/" + HostTestsFile: "package xhost_test\n",
		"node/node_test.go":      pkgFile(passTest, "node"),
	})
	pkgs, err := ListGoPackages(t.Context(), root, "./...")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, p := range pkgs {
		got[p.Dir] = p.NeedsNoNode
	}
	if want := map[string]bool{"host": true, "xhost": true, "node": false}; !maps.Equal(got, want) {
		t.Errorf("NeedsNoNode by package: %v, want %v", got, want)
	}
}

const (
	passTest = "package %s\n\nimport \"testing\"\n\nfunc TestPass(t *testing.T) {}\n"
	labTest  = "package %s\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestNeedsTheLab(t *testing.T) {\n\tif os.Getenv(\"THINKPOL_LAB\") == \"\" {\n\t\tt.Skip(\"needs the lab\")\n\t}\n}\n"
	failTest = "package %s\n\nimport \"testing\"\n\nfunc TestFail(t *testing.T) { t.Fatal(\"broken\") }\n"
)

// TestGoTestOnHost: packages run on the host pass or fail as their tests
// do; one whose test skips for want of the lab fails, though the run's
// own environment has THINKPOL_LAB set (a node's, or a user's): a package
// that needs a node can't pass on the host unseen.
func TestGoTestOnHost(t *testing.T) {
	needGoTool(t)
	isolateGoEnv(t)
	t.Setenv("THINKPOL_LAB", "1")
	root := writeModule(t, map[string]string{
		"pass/pass_test.go": pkgFile(passTest, "pass"),
		"lab/lab_test.go":   pkgFile(labTest, "lab"),
		"fail/fail_test.go": pkgFile(failTest, "fail"),
	})
	pkgs := []GoPackage{
		{ImportPath: "example.net/tagged/pass", Dir: "pass", NeedsNoNode: true},
		{ImportPath: "example.net/tagged/lab", Dir: "lab", NeedsNoNode: true},
		{ImportPath: "example.net/tagged/fail", Dir: "fail", NeedsNoNode: true},
	}
	var out syncBuffer
	results, err := GoTestOnHost(t.Context(), root, pkgs, &out, nil, "-test.count=1")
	if err != nil {
		t.Fatalf("GoTestOnHost: %v\n%s", err, out.String())
	}
	got := map[string]GoTestResult{}
	for _, r := range results {
		got[r.ImportPath] = r
	}
	if r := got["example.net/tagged/pass"]; r.Failed || r.Tests != (TestTally{Passed: 1}) || r.Elapsed <= 0 {
		t.Errorf("pass: %+v", r)
	}
	if r := got["example.net/tagged/lab"]; !r.Failed || r.Tests != (TestTally{Skipped: 1}) {
		t.Errorf("a test needing the lab: %+v, want failed with its skip", r)
	}
	if r := got["example.net/tagged/fail"]; !r.Failed || r.Tests != (TestTally{Failed: 1}) {
		t.Errorf("fail: %+v", r)
	}
	s := out.String()
	for _, want := range []string{
		"=== lab gotest (on the host) example.net/tagged/pass\n",
		"lab gotest example.net/tagged/lab: 1 tests skipped on the host",
		"lab gotest example.net/tagged/pass: took ",
		"broken",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("output lacks %q:\n%s", want, s)
		}
	}
	if len(results) != 3 {
		t.Errorf("%d results, want 3: %+v", len(results), results)
	}
}

// TestHostRunReadsGoTestJSON: a package's events become one block of
// output and a result: a cached pass has no time, a build failure fails
// its package and shows its output, and lines that aren't events pass
// through.
func TestHostRunReadsGoTestJSON(t *testing.T) {
	in := `{"Action":"start","Package":"x/a"}
{"Action":"run","Package":"x/a","Test":"TestA"}
{"Action":"output","Package":"x/a","Test":"TestA","Output":"=== RUN   TestA\n"}
{"Action":"output","Package":"x/a","Test":"TestA","Output":"--- PASS: TestA (0.00s)\n"}
{"Action":"pass","Package":"x/a","Test":"TestA","Elapsed":0}
{"Action":"output","Package":"x/a","Output":"ok  \tx/a\t(cached)\n"}
{"Action":"pass","Package":"x/a","Elapsed":3.2}
{"ImportPath":"x/b [x/b.test]","Action":"build-output","Output":"b_test.go:3:1: syntax error\n"}
{"ImportPath":"x/b [x/b.test]","Action":"build-fail"}
{"Action":"start","Package":"x/b"}
{"Action":"output","Package":"x/b","Output":"FAIL\tx/b [build failed]\n"}
{"Action":"fail","Package":"x/b","Elapsed":0,"FailedBuild":"x/b [x/b.test]"}
go: downloading example.net/m v1.0.0
{"Action":"start","Package":"x/c"}
{"Action":"output","Package":"x/c","Output":"--- PASS: TestC (1.00s)\n"}
{"Action":"pass","Package":"x/c","Elapsed":1.5}
`
	var w strings.Builder
	h := hostRun{w: &w, wanted: map[string]GoPackage{"x/a": {}, "x/b": {}, "x/c": {}}, outs: map[string]*hostOutput{}}
	if err := h.read(strings.NewReader(in)); err != nil {
		t.Fatal(err)
	}
	want := []GoTestResult{
		{ImportPath: "x/a", Cached: true, Tests: TestTally{Passed: 1}},
		{ImportPath: "x/b", Failed: true},
		{ImportPath: "x/c", Tests: TestTally{Passed: 1}, Elapsed: 1500 * time.Millisecond},
	}
	if !slices.Equal(h.results, want) {
		t.Errorf("results:\n%+v\nwant:\n%+v", h.results, want)
	}
	s := w.String()
	for _, part := range []string{
		"=== lab gotest (on the host) x/a (cached)\n",
		"=== lab gotest (on the host) x/b\nb_test.go:3:1: syntax error\nFAIL\tx/b [build failed]\n",
		"go: downloading example.net/m v1.0.0\n",
		"lab gotest x/c: took 1.5s (on the host)\n",
	} {
		if !strings.Contains(s, part) {
			t.Errorf("output lacks %q:\n%s", part, s)
		}
	}
	if strings.Contains(s, "lab gotest x/a: took") {
		t.Errorf("a cached package has a time:\n%s", s)
	}
}

// TestHostOutputBounded: a package's output past hostOutputLimit isn't
// held, and its report says how much was cut.
func TestHostOutputBounded(t *testing.T) {
	var w strings.Builder
	h := hostRun{w: &w, wanted: map[string]GoPackage{"x/a": {}}, outs: map[string]*hostOutput{}}
	chunk := strings.Repeat("y", 1<<20)
	for range 10 {
		h.out("x/a").add(chunk)
	}
	h.end(hostEvent{Action: "pass", Package: "x/a"})
	if w.Len() > hostOutputLimit+1024 || !strings.Contains(w.String(), "2097152 bytes of x/a's output cut") {
		t.Errorf("%d bytes written, cut note %v", w.Len(), strings.Contains(w.String(), "cut"))
	}
}
