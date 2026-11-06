package main

import (
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
