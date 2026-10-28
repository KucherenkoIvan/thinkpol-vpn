//go:build lab

package lab

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A second run from this checkout (labctl gotest, its own process) builds
// and runs the same package's tests while this run's lab has them built:
// both pass, this run's test binary is the one it built, and the other
// run leaves no binaries behind.
func TestAnotherRunFromTheCheckoutBuildsItsOwnBinaries(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	const pkgPattern = "./lab/ip"
	pkgs, err := ListGoPackages(ctx, root, pkgPattern)
	if err != nil || len(pkgs) != 1 {
		t.Fatalf("packages %v: %v", pkgs, err)
	}
	l := Start(t, GoTestTopology())
	node := l.Node("gotest")
	node.RunGoTests(t, pkgPattern)
	bin := filepath.Join(l.binDir, "tests", testBinaryName(pkgs[0]))
	before, err := os.Stat(bin)
	if err != nil {
		t.Fatal(err)
	}

	// Its own project name: labs of this checkout's other runs (make
	// lab-test's node phase tests this package too) keep theirs.
	other := exec.CommandContext(ctx, "go", "-C", root, "run", "./lab/labctl", "gotest", pkgPattern)
	other.Env = append(os.Environ(), fmt.Sprintf("%s=bindir-%d", ProjectEnv, os.Getpid()))
	if out, err := other.CombinedOutput(); err != nil {
		t.Fatalf("the other run: %v\n%s", err, out)
	}

	after, err := os.Stat(bin)
	if err != nil {
		t.Fatalf("this run's test binary after the other run: %v", err)
	}
	if !os.SameFile(before, after) || !after.ModTime().Equal(before.ModTime()) {
		t.Errorf("the other run replaced this run's test binary %s", bin)
	}
	node.RunGoTests(t, pkgPattern)

	// Every run directory left is a live run's or a kept lab's: the other
	// run removed its own.
	unlock, err := lockBinRoot(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	entries, err := os.ReadDir(binRoot(root))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), runBinariesPrefix) {
			continue
		}
		path := filepath.Join(binRoot(root), e.Name())
		live, err := runBinariesLive(path)
		if err != nil {
			t.Fatal(err)
		}
		kept, err := keptBy(path)
		if err != nil {
			t.Fatal(err)
		}
		if !live && len(kept) == 0 {
			t.Errorf("%s was left behind by a run that ended", e.Name())
		}
	}
}
