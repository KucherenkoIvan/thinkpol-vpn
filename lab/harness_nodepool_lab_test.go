//go:build lab

package lab

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TestHarnessNodePoolRetiresWhatALeftoverSpoils: the node phase's pool
// hands a package's lab to the next package once the reset put back what
// the package left (a link, a file under /tmp, a process), and logs what
// it undid in the package's output; a package that leaves what the reset
// can't put back (a file outside /etc changed), or that failed, gets the
// lab retired, and the next package a lab of its own, started afresh.
func TestHarnessNodePoolRetiresWhatALeftoverSpoils(t *testing.T) {
	t.Parallel()
	// No bound of its own: a lab start waits for a slot as long as the
	// lab's budget lets it (labBudget), within the test binary's deadline.
	ctx := t.Context()
	root, err := Root()
	if err != nil {
		t.Fatal(err)
	}
	checkout, err := CheckoutProject(root)
	if err != nil {
		t.Fatal(err)
	}
	run, err := runID()
	if err != nil {
		t.Fatal(err)
	}
	cwd, _ := os.Getwd()
	pool := newNodePool(1, 5, func(i int) string { return ownTestProject(checkout, run, cwd, fmt.Sprintf("%s-%d", t.Name(), i)) })
	var stats bytes.Buffer
	defer func() {
		if err := pool.close(&stats, "packages"); err != nil {
			t.Error(err)
		}
		t.Logf("%s", stats.String())
	}()

	// use runs one package in the pool, verbose as with -v unless
	// quiet: in, run in the lab's node, says what it found; failed fails
	// the package. It returns the lab's project and the package's output.
	use := func(name string, failed, quiet bool, in func(n *Node) string) (project, found, out string) {
		t.Helper()
		var w bytes.Buffer
		res := pool.goTest(ctx, time.Now(), root, name, &w, !quiet, func(n *Node) labRun {
			project, found = n.lab.Project, in(n)
			if failed {
				return labRun{testErr: errors.New("a test failed")}
			}
			return labRun{}
		})
		if res.labErr != nil {
			t.Fatalf("%s: lab: %v\n%s", name, res.labErr, w.String())
		}
		return project, found, w.String()
	}
	clean := func(n *Node) string {
		return n.MustExec(t, "sh", "-c", "ip -o link show leftover0 2>/dev/null; ls /tmp/leftover 2>/dev/null; pgrep -f '^sleep 1000'; true")
	}

	first, _, out := use("example.net/leaves-what-the-reset-undoes", false, false, func(n *Node) string {
		n.MustExec(t, "sh", "-ec", `
ip link add leftover0 type dummy
echo x > /tmp/leftover
setsid sleep 1000 </dev/null >/dev/null 2>&1 &
`)
		return ""
	})
	if !strings.Contains(out, "the reset undid what was left behind:") || !strings.Contains(out, "leftover0") {
		t.Errorf("the package's output doesn't say what the reset undid:\n%s", out)
	}
	again, found, _ := use("example.net/gets-it-back", false, true, clean)
	if again != first || found != "" {
		t.Fatalf("the next package got lab %s (want %s back) with %q left", again, first, found)
	}

	spoiled, _, out := use("example.net/changes-a-file-outside-etc", false, true, func(n *Node) string {
		n.MustExec(t, "sh", "-ec", `echo '# changed' >> /var/lib/dpkg/status`)
		return ""
	})
	if !strings.Contains(out, "didn't hold") || !strings.Contains(out, "/var/lib/dpkg/status") {
		t.Errorf("without -v, the package's output doesn't say why its lab's reset didn't hold:\n%s", out)
	}
	if spoiled != first {
		t.Fatalf("got lab %s, want %s, the pool's one lab", spoiled, first)
	}
	fresh, found, out := use("example.net/after-the-spoiled-one", true, false, func(n *Node) string {
		return n.MustExec(t, "sh", "-c", "grep -c '# changed' /var/lib/dpkg/status; true")
	})
	if fresh == spoiled || strings.TrimSpace(found) != "0" {
		t.Fatalf("a lab whose check failed was handed on (%s, %s lines changed):\n%s", fresh, strings.TrimSpace(found), out)
	}
	afterFailed, found, out := use("example.net/after-the-failed-one", false, false, clean)
	if afterFailed == fresh || found != "" {
		t.Fatalf("a failed package's lab %s was handed on (got %s, %q left):\n%s", fresh, afterFailed, found, out)
	}

	retired := pool.Stats().Retired
	if len(retired) != 2 || !strings.Contains(retired[0], "example.net/changes-a-file-outside-etc (its reset didn't hold)") || !strings.Contains(retired[1], "example.net/after-the-spoiled-one (it failed)") {
		t.Errorf("retired: %q, want the spoiled lab's and the failed package's", retired)
	}
}
