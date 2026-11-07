package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

func TestGotestVerdict(t *testing.T) {
	passed := lab.GoTestResult{ImportPath: "x/a", Tests: lab.TestTally{Passed: 2}}
	skipped := lab.GoTestResult{ImportPath: "x/b", Tests: lab.TestTally{Skipped: 1}}
	failed := lab.GoTestResult{ImportPath: "x/c", Failed: true, Tests: lab.TestTally{Failed: 1}}
	noneRan := lab.GoTestResult{ImportPath: "x/d"}
	for _, tc := range []struct {
		name        string
		results     []lab.GoTestResult
		failSkipped bool
		wantErr     []string // substrings; none: the run passes
	}{
		{"all skipped, lab-test", []lab.GoTestResult{skipped}, false, nil},
		{"all skipped, lab-gotest", []lab.GoTestResult{passed, skipped}, true, []string{"every test skipped in: x/b"}},
		{"skipped in the node, run on the host", []lab.GoTestResult{skipped, {ImportPath: "x/b", Tests: lab.TestTally{Passed: 1}}}, true, nil},
		{"run matched nothing in one package", []lab.GoTestResult{passed, noneRan}, true, nil},
		{"no test ran", []lab.GoTestResult{noneRan}, true, []string{"no test ran"}},
		{"no test ran, lab-test", []lab.GoTestResult{noneRan}, false, nil},
		{"failure and skips", []lab.GoTestResult{failed, skipped}, true, []string{"failed: x/c", "every test skipped in: x/b"}},
		{"failure", []lab.GoTestResult{failed}, false, []string{"failed: x/c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := gotestVerdict(tc.results, tc.failSkipped)
			if len(tc.wantErr) == 0 {
				if err != nil {
					t.Fatalf("gotestVerdict: %v, want nil", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("gotestVerdict: nil, want an error with %q", tc.wantErr)
			}
			for _, want := range tc.wantErr {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("gotestVerdict: %v, want it to contain %q", err, want)
				}
			}
		})
	}
}

func TestGotestWithNoPackagesWithTests(t *testing.T) {
	if testing.Short() {
		t.Skip("runs the go command")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go command here") // a lab node has test binaries but no toolchain
	}
	t.Setenv("GOWORK", "off")
	t.Setenv("GOFLAGS", "-mod=mod")
	root := t.TempDir()
	for name, body := range map[string]string{
		"go.mod":         "module example.net/notests\n\ngo 1.26\n",
		"plain/plain.go": "package plain\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	patterns := []string{"./..."}
	if err := gotest(t.Context(), root, gotestOptions{tagged: true}, nil, nil, patterns); err != nil {
		t.Errorf("without -fail-skipped: %v, want nil", err)
	}
	err := gotest(t.Context(), root, gotestOptions{tagged: true, failSkipped: true}, nil, nil, patterns)
	if err == nil || !strings.Contains(err.Error(), "no packages with tests") {
		t.Errorf("with -fail-skipped: %v, want a no-packages error", err)
	}
}

// labctl down -run with an empty or invalid id (-run "$THINKPOL_LAB_RUN",
// the variable unset) fails before asking Docker anything, instead of
// becoming a plain down that removes every lab of the checkout.
func TestDownRunRejectsABadIDBeforeDocker(t *testing.T) {
	called := fakeDockerMarker(t)
	root := t.TempDir()

	for _, id := range []string{"", "Bad-ID", "r1-x", "123456789"} {
		if err := down(t.Context(), root, []string{"-run", id}); err == nil {
			t.Errorf("down -run %q: no error", id)
		}
		if _, err := os.Stat(called); err == nil {
			t.Fatalf("down -run %q asked Docker", id)
		}
	}
}

// labctl down with a positional argument (down r1 -run r1, or down r1 with
// -run forgotten) fails before asking Docker anything: flag parsing stops at
// the argument, so -run would go unseen and the whole checkout's labs go.
func TestDownRejectsPositionalArgumentsBeforeDocker(t *testing.T) {
	called := fakeDockerMarker(t)
	root := t.TempDir()

	for _, args := range [][]string{{"r1"}, {"r1", "-run", "r1"}, {"-tests", "r1"}} {
		if err := down(t.Context(), root, args); err == nil {
			t.Errorf("down %q: no error", args)
		}
		if _, err := os.Stat(called); err == nil {
			t.Fatalf("down %q asked Docker", args)
		}
	}
}

// fakeDockerMarker puts a failing docker on PATH that creates the file it
// returns when called.
func fakeDockerMarker(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	called := filepath.Join(dir, "called")
	script := "#!/bin/sh\ntouch '" + called + "'\necho fake docker >&2\nexit 1\n"
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	return called
}
