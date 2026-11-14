package main

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
)

// rollback takes no arguments, and refuses to run but as root before it
// looks at the host. As root (a lab node) it would clear that node's
// network, which other packages' tests use at the same time. An OS with
// no data plane (Windows, whose os.Geteuid is -1) refuses before the root
// check, as unsupported.
func TestRollbackNeedsRootAndNoArguments(t *testing.T) {
	if code, _, stderr := runCLI(t, "rollback", "now"); code != exitUsage || !strings.Contains(stderr, "usage") {
		t.Errorf("rollback now: exit %d\n%s", code, stderr)
	}
	if os.Geteuid() == 0 {
		t.Skip("as root rollback would clear this host")
	}
	want, wantCode := agent.ErrRollbackNeedsRoot.Error(), exitNoPerm
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		want, wantCode = agent.ErrUnsupported.Error(), exitFailure
	}
	if code, stdout, stderr := runCLI(t, "rollback"); code != wantCode || stdout != "" || !strings.Contains(stderr, want) {
		t.Errorf("rollback: exit %d\n%s%s", code, stdout, stderr)
	}
}
