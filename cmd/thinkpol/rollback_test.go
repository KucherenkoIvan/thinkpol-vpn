package main

import (
	"os"
	"strings"
	"testing"
)

// rollback takes no arguments, and refuses to run but as root before it
// looks at the host. As root (a lab node) it would clear that node's
// network, which other packages' tests use at the same time.
func TestRollbackNeedsRootAndNoArguments(t *testing.T) {
	if code, _, stderr := runCLI(t, "rollback", "now"); code != 2 || !strings.Contains(stderr, "usage") {
		t.Errorf("rollback now: exit %d\n%s", code, stderr)
	}
	if os.Geteuid() == 0 {
		t.Skip("as root rollback would clear this host")
	}
	if code, stdout, stderr := runCLI(t, "rollback"); code != 1 || stdout != "" || !strings.Contains(stderr, "run it as root (sudo)") {
		t.Errorf("rollback: exit %d\n%s%s", code, stdout, stderr)
	}
}
