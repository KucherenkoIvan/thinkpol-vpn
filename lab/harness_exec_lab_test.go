//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// Helpers the harness tests reach, shared with other lab tests: the
// harness hash covers this file (TestTheHarnessHashCoversWhatItsTestsReach).

// execTimeout bounds a one-shot check's execs: the check runs once and
// fails with what it saw. pollTimeout bounds one read inside a poll: the
// poll's deadline is what bounds the wait, a read leaves it room to retry.
const (
	execTimeout = 2 * time.Minute
	pollTimeout = 10 * time.Second
)

// execResult runs one command in the node, bounded by timeout, and
// returns its whole result: for callers that classify the exit.
func execResult(n *lab.Node, timeout time.Duration, args ...string) (lab.Result, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return n.Exec(ctx, args...)
}

// execRead runs one command in the node and returns its stdout.
func execRead(n *lab.Node, timeout time.Duration, args ...string) (string, error) {
	res, err := execResult(n, timeout, args...)
	if err != nil {
		return "", fmt.Errorf("%w\nstdout:\n%s", err, res.Stdout)
	}
	return res.Stdout, nil
}

// pingNoReply says whether a failed ping got no reply: exit 1 and ping's
// own " 0 received" summary: the echo left and nothing came back. A censor
// probe needs this one: to call a path blocked, the probe must have
// crossed the wire, which a route the sender lacks (pingNoReplyOrRoute)
// doesn't show. Exec failures are an unknown state.
func pingNoReply(res lab.Result) bool {
	return res.ExitCode == 1 && strings.Contains(res.Stdout, " 0 received")
}

// pingNoReplyOrRoute says whether a failed ping shows, by ping's own
// account, that the path doesn't work: no reply (pingNoReply), or the
// sender's kernel refusing for want of a route, which sends nothing (exit
// 2 with "Network is unreachable" or "No route to host"). Ping's other
// exit-2 failures are usage errors (an unknown interface) and say nothing.
func pingNoReplyOrRoute(res lab.Result) bool {
	out := res.Stdout + res.Stderr
	return pingNoReply(res) ||
		res.ExitCode == 2 && (strings.Contains(out, "Network is unreachable") || strings.Contains(out, "No route to host"))
}

// pingAnswers pings from n (args after "ping"), with what ping printed:
// true for a reply, false for ping's own "no" as no tells it (one of the
// classifiers above, measured for the case), anything else an error (an
// unknown state, never a pass).
func pingAnswers(n *lab.Node, no func(lab.Result) bool, args ...string) (bool, string, error) {
	res, err := execResult(n, execTimeout, append([]string{"ping"}, args...)...)
	out := res.Stdout + res.Stderr
	switch {
	case err == nil:
		return true, out, nil
	case no(res):
		return false, out, nil
	}
	return false, out, fmt.Errorf("ping %s on %s says nothing about the path: %w\n%s", strings.Join(args, " "), n.Name, err, out)
}

// noPing fails the test if ping (args after "ping") from n gets a reply,
// and at once if ping says nothing about the path (pingAnswers). A route
// the sender's kernel lacks counts as no path: nothing is sent.
func noPing(t *testing.T, n *lab.Node, args ...string) {
	t.Helper()
	answered, out, err := pingAnswers(n, pingNoReplyOrRoute, args...)
	if err != nil {
		t.Fatal(err)
	}
	if answered {
		t.Errorf("ping %s from %s answered:\n%s", strings.Join(args, " "), n.Name, out)
	}
}
