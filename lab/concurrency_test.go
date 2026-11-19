package lab

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"testing"
)

// TestMakefileConcurrencyFollowsLabSlots: make lab-test starts as many
// labs at once as the lab slot cap allows, and no more of its CPU-bound
// builds than LAB_P. The Makefile's LAB_SLOTS reads the cap's variable,
// with the cap's own default; every run of lab tests in a stream or the
// harness phase has -parallel LAB_SLOTS (Go's default, GOMAXPROCS, would
// leave slots idle on a machine with fewer cores than slots); the node
// phase runs LAB_SLOTS packages at once and builds LAB_P at once.
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

	binaries := regexp.MustCompile(`go tool test2json [^;|]*`).FindAll(mk, -1)
	goTests := regexp.MustCompile(`go test -tags lab [^;|]*`).FindAll(mk, -1)
	if len(binaries) < 2 || len(goTests) < 3 {
		t.Fatalf("the Makefile runs %d lab test binaries and %d go tests of lab packages: want both streams' and the harness's", len(binaries), len(goTests))
	}
	binaryParallel := regexp.MustCompile(` -test\.parallel=\$\(LAB_SLOTS\) `)
	for _, run := range binaries {
		if !binaryParallel.Match(run) {
			t.Errorf("a lab test binary without -test.parallel=$(LAB_SLOTS): %s", run)
		}
	}
	compile := regexp.MustCompile(` -c `)
	goTestParallel := regexp.MustCompile(` -parallel \$\(LAB_SLOTS\) `)
	for _, run := range goTests {
		if !compile.Match(run) && !goTestParallel.Match(run) {
			t.Errorf("a go test of lab packages without -parallel $(LAB_SLOTS): %s", run)
		}
	}

	if !regexp.MustCompile(`(?m)^\t.*"\$\$labctl" gotest -p \$\(LAB_SLOTS\) -build-p \$\(LAB_P\) -times "\$\$tmp/node\.times"`).Match(mk) {
		t.Error("the node phase doesn't run gotest -p $(LAB_SLOTS) -build-p $(LAB_P)")
	}
}
