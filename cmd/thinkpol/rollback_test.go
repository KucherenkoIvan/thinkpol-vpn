package main

import (
	"context"
	"fmt"
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
	if code, _, stderr := runCLI(t, "rollback", "now"); code != 2 || !strings.Contains(stderr, "usage") {
		t.Errorf("rollback now: exit %d\n%s", code, stderr)
	}
	if os.Geteuid() == 0 {
		t.Skip("as root rollback would clear this host")
	}
	want := agent.ErrRollbackNeedsRoot.Error()
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		want = agent.ErrUnsupported.Error()
	}
	if code, stdout, stderr := runCLI(t, "rollback"); code != 1 || stdout != "" || !strings.Contains(stderr, want) {
		t.Errorf("rollback: exit %d\n%s%s", code, stdout, stderr)
	}
}

// A command refused because another process holds the host lock exits
// 75 (EX_TEMPFAIL: try again), saying why; other failures exit 1.
func TestAHeldHostLockExitsTempFail(t *testing.T) {
	const path = "test host lock held"
	var fail error
	commands[path] = command{path: path, hidden: true, run: func(context.Context, env, []string) error { return fail }}
	t.Cleanup(func() { delete(commands, path) })
	held := fmt.Errorf("%w (it holds the test's lock)", agent.ErrAnotherAgent)
	for _, c := range []struct {
		err  error
		code int
	}{{tempFailError{held}, 75}, {held, 1}} {
		fail = c.err
		if code, _, stderr := runCLI(t, "test", "host", "lock", "held"); code != c.code || stderr != "thinkpol "+path+": "+held.Error()+"\n" {
			t.Errorf("%v: exit %d, want %d\n%s", c.err, code, c.code, stderr)
		}
	}
}
