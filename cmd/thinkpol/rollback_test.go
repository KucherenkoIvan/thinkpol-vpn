package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/agent"
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
	if code, stdout, stderr := runCLI(t, "rollback"); code != 1 || stdout != "" || !strings.Contains(stderr, agent.ErrRollbackNeedsRoot.Error()) {
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
