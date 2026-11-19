package lab

import (
	"context"
	"encoding/json"
	"fmt"
	"go/scanner"
	"go/token"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// needsNode matches the code (identifiers and strings, not comments) of a
// test that needs a lab node, or that a test on the host must not reach:
// the lab's variable, root, namespaces, mounts and the root's sandboxing,
// capabilities, the kernel's network configuration (netlink, nftables, a
// TUN) and running other programs.
var needsNode = regexp.MustCompile(`THINKPOL_LAB|Geteuid|Getuid|Unshare|Setns|CLONE_NEW|nsthread|netns|Mount|PivotRoot|Chroot|Prctl|CAP_|netlink|NETLINK|nftables|/dev/net/tun|^os/exec$`)

// TestNodelessPackagesNeedNoNode: no package with HostTestsFile builds, for
// its tests, code of this module that needs a node (needsNode): its own
// files and test files, and every package of this module its tests
// import, directly or not (test helpers, production code). Such tests
// would skip or fail on the host, prove less there than in a node, or act
// on the host. It is a lint: what stops a test on the host from changing
// it is that labctl never runs the host's packages as root
// (hostRunsNodeless), so the kernel refuses such a test. Every package
// marked is listed, so a mark can't go unchecked.
func TestNodelessPackagesNeedNoNode(t *testing.T) {
	needGoTool(t)
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	marked, findings, err := nodelessFindings(t.Context(), root, "./...")
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		t.Error(f)
	}
	if len(marked) == 0 {
		t.Fatalf("no package has %s: the check checks nothing", HostTestsFile)
	}
	t.Logf("packages whose tests run on the host: %s", strings.Join(marked, " "))
}

// TestNodelessFindingsSeeHelpersAndCode: the check finds what needs a node
// in a test helper and in production code a marked package's tests
// import, not in a comment, and not in a package without the mark.
func TestNodelessFindingsSeeHelpersAndCode(t *testing.T) {
	needGoTool(t)
	isolateGoEnv(t)
	root := writeModule(t, map[string]string{
		"labtest/labtest.go":          "package labtest\n\nimport \"os\"\n\nfunc InLab() bool { return os.Getenv(\"THINKPOL_LAB\") != \"\" }\n",
		"helped/helped_test.go":       "package helped\n\nimport (\n\t\"testing\"\n\n\t\"example.net/tagged/labtest\"\n)\n\nfunc TestX(t *testing.T) { _ = labtest.InLab() }\n",
		"helped/" + HostTestsFile:     "package helped\n",
		"tunnel/tunnel.go":            "package tunnel\n\nimport \"os\"\n\nfunc Open() error { _, err := os.Open(\"/dev/net/tun\"); return err }\n",
		"tunneluser/tunneluser.go":    "package tunneluser\n\nimport \"example.net/tagged/tunnel\"\n\nvar Open = tunnel.Open\n",
		"tunneluser/x_test.go":        pkgFile(passTest, "tunneluser_test"),
		"tunneluser/" + HostTestsFile: "package tunneluser_test\n",
		"commented/c.go":              "package commented\n\n// Mount and netns only in a comment.\nfunc F() {}\n",
		"commented/c_test.go":         pkgFile(passTest, "commented"),
		"commented/" + HostTestsFile:  "package commented\n",
		"node/node_test.go":           pkgFile(labTest, "node"),
	})
	marked, findings, err := nodelessFindings(t.Context(), root, "./...")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"example.net/tagged/commented", "example.net/tagged/helped", "example.net/tagged/tunneluser"}; !slices.Equal(marked, want) {
		t.Errorf("marked %v, want %v", marked, want)
	}
	all := strings.Join(findings, "\n")
	if len(findings) != 2 ||
		!strings.Contains(all, "example.net/tagged/helped has "+HostTestsFile+", but labtest/labtest.go:5 uses \"THINKPOL_LAB\"") ||
		!strings.Contains(all, "example.net/tagged/tunneluser has "+HostTestsFile+", but tunnel/tunnel.go:5 uses \"/dev/net/tun\"") {
		t.Errorf("findings:\n%s\nwant the helper's THINKPOL_LAB and the imported code's /dev/net/tun, nothing else", all)
	}
}

// nodelessFindings lists the packages of patterns marked with
// HostTestsFile and what in the code their tests build with needs a node.
func nodelessFindings(ctx context.Context, root string, patterns ...string) (marked, findings []string, err error) {
	pkgs, err := ListGoPackages(ctx, root, patterns...)
	if err != nil {
		return nil, nil, err
	}
	for _, p := range pkgs {
		if !p.NeedsNoNode {
			continue
		}
		marked = append(marked, p.ImportPath)
		files, err := nodelessScanFiles(ctx, root, p)
		if err != nil {
			return nil, nil, err
		}
		for _, f := range files {
			src, err := os.ReadFile(f)
			if err != nil {
				return nil, nil, err
			}
			rel, _ := filepath.Rel(root, f)
			for _, hit := range codeMatches(src, needsNode) {
				findings = append(findings, fmt.Sprintf("%s has %s, but %s:%d uses %q: its tests need a node", p.ImportPath, HostTestsFile, filepath.ToSlash(rel), hit.line, hit.text))
			}
		}
	}
	return marked, findings, nil
}

// nodelessScanFiles lists the files, as built for linux, of the code a
// package's tests build with from this module: its own files and test
// files, and the files of every package of this module they import,
// directly or not (their own tests aren't built in).
func nodelessScanFiles(ctx context.Context, root string, p GoPackage) ([]string, error) {
	res, err := run(ctx, nil, []string{"GOOS=linux", "CGO_ENABLED=0"}, "go", "-C", root, "list", "-deps", "-test", "-json=ImportPath,Dir,GoFiles,TestGoFiles,XTestGoFiles,Module", "./"+p.Dir)
	if err != nil {
		return nil, err
	}
	var files []string
	dec := json.NewDecoder(strings.NewReader(res.Stdout))
	for dec.More() {
		var d struct {
			ImportPath                         string
			Dir                                string
			GoFiles, TestGoFiles, XTestGoFiles []string
			Module                             *struct{ Main bool }
		}
		if err := dec.Decode(&d); err != nil {
			return nil, err
		}
		// "x [y.test]" is x built for y's tests; y.test is the generated
		// main package.
		pkg, _, _ := strings.Cut(d.ImportPath, " ")
		if d.Module == nil || !d.Module.Main || strings.HasSuffix(pkg, ".test") {
			continue
		}
		names := d.GoFiles
		if pkg == p.ImportPath || pkg == p.ImportPath+"_test" {
			names = slices.Concat(d.GoFiles, d.TestGoFiles, d.XTestGoFiles)
		}
		for _, n := range names {
			if f := filepath.Join(d.Dir, n); !slices.Contains(files, f) {
				files = append(files, f)
			}
		}
	}
	return files, nil
}

type codeMatch struct {
	line int
	text string
}

// codeMatches finds re in a Go file's identifiers and string literals
// (unquoted), not in its comments.
func codeMatches(src []byte, re *regexp.Regexp) []codeMatch {
	fset := token.NewFileSet()
	var s scanner.Scanner
	s.Init(fset.AddFile("", fset.Base(), len(src)), src, nil, 0)
	var out []codeMatch
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			return out
		}
		switch tok {
		case token.STRING:
			if u, err := strconv.Unquote(lit); err == nil {
				lit = u
			}
		case token.IDENT:
		default:
			continue
		}
		if m := re.FindString(lit); m != "" {
			out = append(out, codeMatch{line: fset.Position(pos).Line, text: m})
		}
	}
}

// TestNodelessScanFiles: a marked package's scan covers its own test
// files and the files of this module's packages its tests import, test
// helpers and production code, but not those packages' own tests, nor
// code outside the module.
func TestNodelessScanFiles(t *testing.T) {
	needGoTool(t)
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	files, err := nodelessScanFiles(t.Context(), root, GoPackage{ImportPath: modulePath(t, root) + "/internal/dataplane/path", Dir: "internal/dataplane/path"})
	if err != nil {
		t.Fatal(err)
	}
	var rel []string
	for _, f := range files {
		r, err := filepath.Rel(root, f)
		if err != nil || strings.HasPrefix(r, "..") {
			t.Errorf("%s: outside the module", f)
		}
		rel = append(rel, filepath.ToSlash(r))
	}
	for _, want := range []string{
		"internal/dataplane/path/bind_test.go",                        // its external tests
		"internal/dataplane/path/frame_test.go",                       // its own tests
		"internal/dataplane/path/node.go",                             // its code
		"internal/dataplane/transport/transporttest/transporttest.go", // a test helper
		"internal/dataplane/transport/memory/memory.go",               // production code its tests use
	} {
		if !slices.Contains(rel, want) {
			t.Errorf("scan of path lacks %s: %v", want, rel)
		}
	}
	for _, r := range rel {
		if strings.HasSuffix(r, "_test.go") && !strings.HasPrefix(r, "internal/dataplane/path/") {
			t.Errorf("scan of path has another package's test file %s", r)
		}
	}
}

func modulePath(t *testing.T, root string) string {
	t.Helper()
	res, err := run(t.Context(), nil, nil, "go", "-C", root, "list", "-m")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(res.Stdout)
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
	subTest  = "package %s\n\nimport \"testing\"\n\nfunc TestCases(t *testing.T) {\n\tt.Run(\"unsupported\", func(t *testing.T) { t.Skip(\"not this transport\") })\n}\n"
)

// TestGoTestOnHost: packages run on the host pass or fail as their tests
// do; one whose test skips for want of the lab fails, though the run's
// own environment has THINKPOL_LAB set (a node's, or a user's): a package
// that needs a node can't pass on the host unseen. A subtest that skips
// (a conformance case a transport doesn't have) fails nothing. They build
// without cgo, as in a node, whatever the environment says.
func TestGoTestOnHost(t *testing.T) {
	needGoTool(t)
	isolateGoEnv(t)
	t.Setenv("THINKPOL_LAB", "1")
	t.Setenv("CGO_ENABLED", "1")
	root := writeModule(t, map[string]string{
		"pass/pass_test.go": pkgFile(passTest, "pass"),
		"lab/lab_test.go":   pkgFile(labTest, "lab"),
		"fail/fail_test.go": pkgFile(failTest, "fail"),
		"sub/sub_test.go":   pkgFile(subTest, "sub"),
		"nocgo/env_test.go": "package nocgo\n\nimport (\n\t\"os\"\n\t\"testing\"\n)\n\nfunc TestEnv(t *testing.T) {\n\tif v := os.Getenv(\"CGO_ENABLED\"); v != \"0\" {\n\t\tt.Fatalf(\"CGO_ENABLED=%q\", v)\n\t}\n}\n",
		"nocgo/cgo_test.go": "//go:build cgo\n\n" + pkgFile(failTest, "nocgo"),
	})
	pkgs := []GoPackage{
		{ImportPath: "example.net/tagged/pass", Dir: "pass", NeedsNoNode: true},
		{ImportPath: "example.net/tagged/lab", Dir: "lab", NeedsNoNode: true},
		{ImportPath: "example.net/tagged/fail", Dir: "fail", NeedsNoNode: true},
		{ImportPath: "example.net/tagged/sub", Dir: "sub", NeedsNoNode: true},
		{ImportPath: "example.net/tagged/nocgo", Dir: "nocgo", NeedsNoNode: true},
	}
	var out syncBuffer
	results, err := GoTestOnHost(t.Context(), root, pkgs, 2, &out, nil, "-test.count=1")
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
	if r := got["example.net/tagged/sub"]; r.Failed || r.Tests != (TestTally{Passed: 1}) {
		t.Errorf("a subtest skipping, its test passing: %+v, want a pass", r)
	}
	if r := got["example.net/tagged/nocgo"]; r.Failed || r.Tests != (TestTally{Passed: 1}) {
		t.Errorf("built with CGO_ENABLED=1 in the environment: %+v, want a pass without cgo", r)
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
	if len(results) != len(pkgs) {
		t.Errorf("%d results, want %d: %+v", len(results), len(pkgs), results)
	}
}

// TestGoTestOnHostMissingResult: a package go test never reports on fails,
// and the run says which.
func TestGoTestOnHostMissingResult(t *testing.T) {
	needGoTool(t)
	isolateGoEnv(t)
	root := writeModule(t, map[string]string{"pass/pass_test.go": pkgFile(passTest, "pass")})
	// go test reports pass under its own import path, never this one.
	pkgs := []GoPackage{{ImportPath: "example.net/tagged/ghost", Dir: "pass", NeedsNoNode: true}}
	var out syncBuffer
	results, err := GoTestOnHost(t.Context(), root, pkgs, 1, &out, nil, "-test.count=1")
	if err == nil || !strings.Contains(err.Error(), "without a result for example.net/tagged/ghost") {
		t.Errorf("err %v, want it to name the package without a result\n%s", err, out.String())
	}
	if !slices.ContainsFunc(results, func(r GoTestResult) bool { return r.ImportPath == "example.net/tagged/ghost" && r.Failed }) {
		t.Errorf("results %+v: the package without a result isn't failed", results)
	}
}

// TestHostGoTestCommand: go test compiles and runs builds packages at once
// and builds without cgo, without THINKPOL_LAB from the environment.
func TestHostGoTestCommand(t *testing.T) {
	t.Setenv("THINKPOL_LAB", "1")
	t.Setenv("CGO_ENABLED", "1")
	cmd := hostGoTestCommand(t.Context(), "/src", []GoPackage{{Dir: "a"}, {Dir: "b/c"}}, 3, []string{"X=1"}, []string{"-test.run", "TestA"})
	if want := []string{"go", "-C", "/src", "test", "-json", "-p", "3", "-test.run", "TestA", "./a", "./b/c"}; !slices.Equal(cmd.Args, want) {
		t.Errorf("args %q, want %q", cmd.Args, want)
	}
	var cgo []string
	for _, e := range cmd.Env {
		if strings.HasPrefix(e, "THINKPOL_LAB=") {
			t.Errorf("env has %s", e)
		}
		if strings.HasPrefix(e, "CGO_ENABLED=") {
			cgo = append(cgo, e)
		}
	}
	if !slices.Equal(cgo, []string{"CGO_ENABLED=0"}) || !slices.Contains(cmd.Env, "X=1") {
		t.Errorf("CGO_ENABLED in env: %v; X=1 there: %v", cgo, slices.Contains(cmd.Env, "X=1"))
	}
}

// TestHostRunReadsGoTestJSON: a package's events become one block of
// output and a result: its top-level tests counted (a subtest that skips,
// whose "--- SKIP" go test -json prints unindented, isn't), a cached pass
// (said on the package's own verdict line) without a time, a build failure
// failing its package with its output; lines that aren't events pass
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
{"Action":"run","Package":"x/c","Test":"TestC"}
{"Action":"output","Package":"x/c","Test":"TestC","Output":"    c_test.go:9: ok  \tx/c\t(cached)\n"}
{"Action":"output","Package":"x/c","Test":"TestC/sub","Output":"--- SKIP: TestC/sub (0.00s)\n"}
{"Action":"skip","Package":"x/c","Test":"TestC/sub","Elapsed":0}
{"Action":"output","Package":"x/c","Test":"TestC","Output":"--- PASS: TestC (1.00s)\n"}
{"Action":"pass","Package":"x/c","Test":"TestC","Elapsed":1}
{"Action":"output","Package":"x/c","Output":"ok  \tx/c\t1.5s\n"}
{"Action":"pass","Package":"x/c","Elapsed":1.5}
`
	var w strings.Builder
	h := newHostRun(&w, map[string]GoPackage{"x/a": {}, "x/b": {}, "x/c": {}}, false)
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
		"=== lab gotest (on the host) x/a (cached)\nok  \tx/a\t(cached)\n",
		"=== lab gotest (on the host) x/b\nb_test.go:3:1: syntax error\nFAIL\tx/b [build failed]\n",
		"go: downloading example.net/m v1.0.0\n",
		"=== lab gotest (on the host) x/c\nok  \tx/c\t1.5s\nlab gotest x/c: took 1.5s (on the host)\n",
	} {
		if !strings.Contains(s, part) {
			t.Errorf("output lacks %q:\n%s", part, s)
		}
	}
	if strings.Contains(s, "lab gotest x/a: took") {
		t.Errorf("a cached package has a time:\n%s", s)
	}
}

// TestHostRunFiltersOutput: a package's block holds what go test without
// -v prints: a passing test's output, however long, is dropped, and a
// failing test's kept, its end too when its output runs past the cut; with
// -test.v, a passing test's output stays.
func TestHostRunFiltersOutput(t *testing.T) {
	var in strings.Builder
	ev := func(action, test, output string) {
		b, _ := json.Marshal(hostEvent{Action: action, Package: "x/a", Test: test, Output: output})
		in.Write(append(b, '\n'))
	}
	line := strings.Repeat("y", 1023) + "\n"
	ev("run", "TestNoisy", "")
	ev("output", "TestNoisy", "=== RUN   TestNoisy\n")
	for range 3 << 10 { // 3 MiB of a passing test's logs
		ev("output", "TestNoisy", line)
	}
	ev("output", "TestNoisy", "--- PASS: TestNoisy (0.00s)\n")
	ev("pass", "TestNoisy", "")
	ev("run", "TestLate", "")
	ev("output", "TestLate", "=== RUN   TestLate\n")
	for range 3 << 10 {
		ev("output", "TestLate", line)
	}
	ev("output", "TestLate", "    late_test.go:9: THE LATE FAILURE\n")
	ev("output", "TestLate", "--- FAIL: TestLate (0.00s)\n")
	ev("fail", "TestLate", "")
	ev("output", "", "FAIL\n")
	ev("fail", "", "")
	for _, verbose := range []bool{false, true} {
		var w strings.Builder
		h := newHostRun(&w, map[string]GoPackage{"x/a": {}}, verbose)
		if err := h.read(strings.NewReader(in.String())); err != nil {
			t.Fatal(err)
		}
		s := w.String()
		if !strings.Contains(s, "THE LATE FAILURE") || !strings.Contains(s, "--- FAIL: TestLate") {
			t.Errorf("verbose %v: the late failure cut:\n%.400s", verbose, s)
		}
		if len(s) > 2*testLogKeep+4096 {
			t.Errorf("verbose %v: %d bytes written, want at most the first and last MiB", verbose, len(s))
		}
		if got := strings.Contains(s, "=== RUN   TestNoisy"); got != verbose {
			t.Errorf("verbose %v: the passing test's output there: %v", verbose, got)
		}
	}
}

// TestHostRunFlushesUnreported: a package go test never gave a verdict for
// (it was killed) still shows its output, a test that never ended whole.
func TestHostRunFlushesUnreported(t *testing.T) {
	in := `{"Action":"run","Package":"x/a","Test":"TestHang"}
{"Action":"output","Package":"x/a","Test":"TestHang","Output":"goroutine 1 [running]:\n"}
`
	var w strings.Builder
	h := newHostRun(&w, map[string]GoPackage{"x/a": {}}, false)
	if err := h.read(strings.NewReader(in)); err != nil {
		t.Fatal(err)
	}
	h.flushUnreported()
	if s := w.String(); s != "=== lab gotest (on the host) x/a (no verdict)\ngoroutine 1 [running]:\n" || len(h.results) != 0 {
		t.Errorf("output %q, results %+v", s, h.results)
	}
}
