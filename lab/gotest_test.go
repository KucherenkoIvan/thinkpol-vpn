package lab

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestTallyTestsCountsTopLevelResultsOnly(t *testing.T) {
	out := `=== RUN   TestA
=== RUN   TestA/sub
--- PASS: TestA (0.01s)
    --- PASS: TestA/sub (0.00s)
=== RUN   TestB
    prototype_test.go:120: in-node tests:
        --- PASS: TestRealityClientInterop (1.52s)
        --- SKIP: TestOther (0.00s)
--- SKIP: TestB (0.00s)
=== RUN   TestC
--- FAIL: TestC (0.00s)
    --- SKIP: TestC/sub (0.00s)
FAIL
`
	want := TestTally{Passed: 1, Failed: 1, Skipped: 1}
	if got := TallyTests([]byte(out)); got != want {
		t.Errorf("TallyTests = %+v, want %+v", got, want)
	}
}

func TestOnlySkippedCountsEveryRunOfAPackage(t *testing.T) {
	results := []GoTestResult{
		// In the node the interop test skips; the host's lab test runs it.
		{ImportPath: "x/reality", Tests: TestTally{Skipped: 1}},
		{ImportPath: "x/reality", Tests: TestTally{Passed: 1, Skipped: 1}},
		{ImportPath: "x/host-first", Tests: TestTally{Passed: 1}},
		{ImportPath: "x/host-first", Tests: TestTally{Skipped: 2}},
		{ImportPath: "x/skipped", Tests: TestTally{Skipped: 3}},
		{ImportPath: "x/failed", Failed: true, Tests: TestTally{Failed: 1, Skipped: 2}},
		{ImportPath: "x/none"}, // -run matched nothing here
		{ImportPath: "x/also-skipped", Tests: TestTally{Skipped: 1}},
	}
	want := []string{"x/also-skipped", "x/skipped"}
	if got := OnlySkipped(results); !slices.Equal(got, want) {
		t.Errorf("OnlySkipped = %q, want %q", got, want)
	}
}

// writeModule writes a module of files (slash-separated paths relative to
// its root) and returns its root.
func writeModule(t *testing.T, files map[string]string) string {
	t.Helper()
	// go list reports directories with symlinks resolved (a temp dir may be
	// under one), and package dirs are taken relative to root.
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files["go.mod"] = "module example.net/tagged\n\ngo 1.26\n"
	for name, body := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const (
	untaggedSkip = "package %s\n\nimport \"testing\"\n\nfunc TestNeedsSetUp(t *testing.T) { t.Skip(\"no set-up\") }\n"
	taggedPass   = "//go:build lab\n\npackage %s\n\nimport \"testing\"\n\nfunc TestSetsUp(t *testing.T) {}\n"
	taggedFail   = "//go:build lab\n\npackage %s\n\nimport \"testing\"\n\nfunc TestSetsUp(t *testing.T) { t.Fatal(\"broken\") }\n"
)

// needGoTool skips a test that runs the go command where it can't: under
// -short, and in a lab node, which has test binaries but no toolchain.
func needGoTool(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("runs the go command")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command here")
	}
}

// isolateGoEnv keeps the go command in a test's module from a workspace
// or module flags set around the test run.
func isolateGoEnv(t *testing.T) {
	t.Setenv("GOWORK", "off")
	t.Setenv("GOFLAGS", "-mod=mod")
}

func pkgFile(format, pkg string) string { return strings.Replace(format, "%s", pkg, 1) }

func TestListLabTaggedPackagesFindsPackagesWithLabTaggedTests(t *testing.T) {
	needGoTool(t)
	isolateGoEnv(t)
	root := writeModule(t, map[string]string{
		"plain/plain_test.go": pkgFile(untaggedSkip, "plain"),
		// One test file either way: the same count with and without the tag.
		"pair/pair_test.go":     "//go:build !lab\n\n" + pkgFile(untaggedSkip, "pair"),
		"pair/pair_lab_test.go": pkgFile(taggedPass, "pair"),
		"both/both_test.go":     pkgFile(untaggedSkip, "both"),
		"both/both_lab_test.go": pkgFile(taggedPass, "both"),
		"only/only_lab_test.go": pkgFile(taggedPass, "only"),
		"only/only.go":          "package only\n",
	})
	pkgs, err := ListLabTaggedPackages(t.Context(), root, "./...")
	if err != nil {
		t.Fatal(err)
	}
	want := []GoPackage{
		{ImportPath: "example.net/tagged/both", Dir: "both"},
		{ImportPath: "example.net/tagged/only", Dir: "only"},
		{ImportPath: "example.net/tagged/pair", Dir: "pair"},
	}
	if !slices.Equal(pkgs, want) {
		t.Errorf("ListLabTaggedPackages = %+v, want %+v", pkgs, want)
	}
}

func TestGoTestLabTaggedRunsTheTaggedTests(t *testing.T) {
	needGoTool(t)
	root := writeModule(t, map[string]string{
		"pass/pass_test.go":     pkgFile(untaggedSkip, "pass"),
		"pass/pass_lab_test.go": pkgFile(taggedPass, "pass"),
		"fail/fail_test.go":     pkgFile(untaggedSkip, "fail"),
		"fail/fail_lab_test.go": pkgFile(taggedFail, "fail"),
	})
	isolateGoEnv(t)

	var out syncBuffer
	res, err := GoTestLabTagged(t.Context(), root, GoPackage{ImportPath: "example.net/tagged/pass", Dir: "pass"}, &out, nil, "-test.v")
	if err != nil {
		t.Fatalf("%v\n%s", err, out.String())
	}
	if want := (TestTally{Passed: 1, Skipped: 1}); res.Tests != want || res.Failed {
		t.Errorf("pass: result %+v, want tests %+v, not failed\n%s", res, want, out.String())
	}

	out = syncBuffer{}
	res, err = GoTestLabTagged(t.Context(), root, GoPackage{ImportPath: "example.net/tagged/fail", Dir: "fail"}, &out, nil, "-test.v")
	if err == nil || !res.Failed || res.Tests.Failed != 1 {
		t.Errorf("fail: result %+v, err %v; want a failure\n%s", res, err, out.String())
	}
}
