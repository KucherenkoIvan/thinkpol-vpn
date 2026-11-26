package lab

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// TestMakefileConcurrencyFollowsLabSlots: make lab-test starts as many
// labs at once as the lab slot cap allows, and no more of its CPU-bound
// builds than LAB_P. The Makefile's LAB_SLOTS reads the cap's variable,
// with the cap's own default; every run of lab tests in the default stream
// has -parallel LAB_SLOTS (Go's default, GOMAXPROCS, would leave slots idle
// on a machine with fewer cores than slots), the long stream's
// LAB_LONG_PARALLEL, fewer, so that its minutes-long labs leave the default
// stream its slots, the harness phase LAB_HARNESS_PARALLEL
// (TestMakefileHarnessParallel); the node phase runs LAB_SLOTS packages at
// once and builds LAB_P at once.
func TestMakefileConcurrencyFollowsLabSlots(t *testing.T) {
	mk, err := os.ReadFile(filepath.Join("..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^LAB_SLOTS = \$\(or \$\(` + MaxLabsEnv + `\),([0-9]+)\)$`).FindSubmatch(mk)
	if m == nil {
		t.Fatalf("no LAB_SLOTS = $(or $(%s),<n>) in the Makefile", MaxLabsEnv)
	}
	if n, _ := strconv.Atoi(string(m[1])); n != defaultMaxLabs {
		t.Errorf("the Makefile's LAB_SLOTS defaults to %d, the slot cap to %d", n, defaultMaxLabs)
	}

	binaries := regexp.MustCompile(`go tool test2json [^;|\n]*`).FindAll(mk, -1)
	goTests := regexp.MustCompile(`go test -tags lab [^;|\n]*`).FindAll(mk, -1)
	if len(binaries) < 2 || len(goTests) < 3 {
		t.Fatalf("the Makefile runs %d lab test binaries and %d go tests of lab packages: want both streams' and the harness's", len(binaries), len(goTests))
	}
	lp := regexp.MustCompile(`(?m)^LAB_LONG_PARALLEL \?= ([0-9]+)$`).FindSubmatch(mk)
	if lp == nil {
		t.Fatal("no LAB_LONG_PARALLEL ?= <n> in the Makefile")
	}
	if n, _ := strconv.Atoi(string(lp[1])); n < 1 || n >= defaultMaxLabs/2 {
		t.Errorf("LAB_LONG_PARALLEL defaults to %d: want at least 1 and under half the slot cap's %d", n, defaultMaxLabs)
	}
	binaryParallel := regexp.MustCompile(` -test\.parallel=\$\(LAB_SLOTS\) `)
	binaryLong := regexp.MustCompile(` -test\.parallel=\$\(LAB_LONG_PARALLEL\) .*-test\.run='\$\(LAB_LONG_TESTS\)'`)
	long := 0
	for _, run := range binaries {
		switch {
		case binaryLong.Match(run):
			long++
		case !binaryParallel.Match(run) || strings.Contains(string(run), "$(LAB_LONG_TESTS)"):
			t.Errorf("a lab test binary without -test.parallel=$(LAB_SLOTS), or the long stream's without $(LAB_LONG_PARALLEL): %s", run)
		}
	}
	compile := regexp.MustCompile(` -c `)
	goTestParallel := regexp.MustCompile(` -parallel \$\(LAB_SLOTS\) `)
	goTestLong := regexp.MustCompile(` -parallel \$\(LAB_LONG_PARALLEL\) .*-run '\$\(LAB_LONG_TESTS\)'`)
	harnessParallel := regexp.MustCompile(` -parallel \$\(LAB_HARNESS_PARALLEL\) .*-run '\$\(LAB_HARNESS_RUN\)'`)
	harness := 0
	for _, run := range goTests {
		switch {
		case harnessParallel.Match(run):
			harness++
		case goTestLong.Match(run):
			long++
		case strings.Contains(string(run), "$(LAB_LONG_TESTS)") || !compile.Match(run) && !goTestParallel.Match(run):
			t.Errorf("a go test of lab packages without -parallel $(LAB_SLOTS), or the long stream's without $(LAB_LONG_PARALLEL): %s", run)
		}
	}
	if long != 2 {
		t.Errorf("%d long-stream runs with -parallel $(LAB_LONG_PARALLEL), want 2 (./lab's binary and the other lab packages)", long)
	}
	if harness != 1 {
		t.Errorf("%d harness go tests with -parallel $(LAB_HARNESS_PARALLEL), want 1", harness)
	}

	if !regexp.MustCompile(`(?m)^\t.*"\$\$labctl" gotest -p \$\(LAB_SLOTS\) -build-p \$\(LAB_P\) -times "\$\$tmp/node\.times"`).Match(mk) {
		t.Error("the node phase doesn't run gotest -p $(LAB_SLOTS) -build-p $(LAB_P)")
	}
}

// TestMakefileHarnessParallel: the harness phase runs with -parallel
// LAB_SLOTS, but never under 4, which
// TestHarnessLabStartsOverlapOnDistinctSubnets needs to run instead of
// skip (a skip leaves the harness unremembered, run again every time).
func TestMakefileHarnessParallel(t *testing.T) {
	if testing.Short() {
		t.Skip("runs make")
	}
	if _, err := exec.LookPath("make"); err != nil {
		t.Skip("no make here")
	}
	show := filepath.Join(t.TempDir(), "show.mk")
	if err := os.WriteFile(show, []byte("show-harness-parallel:\n\t@echo $(LAB_HARNESS_PARALLEL)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for slots, want := range map[string]string{"": "12", "1": "4", "2": "4", "3": "4", "4": "4", "5": "5", "16": "16"} {
		cmd := exec.Command("make", "--no-print-directory", "-s", "-C", "..", "-f", "Makefile", "-f", show, "show-harness-parallel")
		cmd.Env = append(os.Environ(), MaxLabsEnv+"="+slots)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("make with %s=%q: %v", MaxLabsEnv, slots, err)
		}
		if got := strings.TrimSpace(string(out)); got != want {
			t.Errorf("%s=%q: the harness phase's -parallel is %s, want %s", MaxLabsEnv, slots, got, want)
		}
	}
}
