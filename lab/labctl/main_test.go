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
