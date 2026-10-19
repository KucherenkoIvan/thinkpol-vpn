//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// The node's network state after start, stop, connect and disconnect.

// execTimeout bounds a one-shot check's execs: the check runs once and
// fails with what it saw. pollTimeout bounds one read inside a poll: the
// poll's deadline is what bounds the wait, a read leaves it room to retry.
const (
	execTimeout = 2 * time.Minute
	pollTimeout = 10 * time.Second
)

// execRead runs one command in the node and returns its stdout.
func execRead(n *lab.Node, timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := n.Exec(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("%w\nstdout:\n%s", err, res.Stdout)
	}
	return res.Stdout, nil
}

// policyRules is the device's policy rules (both families), which a stop
// or a failed start must put back exactly.
func policyRules(n *lab.Node, timeout time.Duration) (string, string, error) {
	v4, err := execRead(n, timeout, "ip", "rule")
	if err != nil {
		return "", "", err
	}
	v6, err := execRead(n, timeout, "ip", "-6", "rule")
	if err != nil {
		return "", "", err
	}
	return v4, v6, nil
}

// routeTableRulesUp says whether the route table's own policy rules
// (priority 5301) are in both families' listings.
func routeTableRulesUp(v4, v6 string) bool {
	return strings.Contains(v4, "5301:") && strings.Contains(v6, "5301:")
}

// routeTableRoutes is everything in the routing tables of the route
// table's protocol (86), IPv4 and IPv6.
func routeTableRoutes(n *lab.Node, timeout time.Duration) (string, string, error) {
	v4, err := execRead(n, timeout, "ip", "-4", "route", "show", "table", "all", "proto", "86")
	if err != nil {
		return "", "", err
	}
	v6, err := execRead(n, timeout, "ip", "-6", "route", "show", "table", "all", "proto", "86")
	if err != nil {
		return "", "", err
	}
	return v4, v6, nil
}

// guardState is the IPv6 leak guard's nftables table's state.
type guardState string

const (
	guardPresent guardState = "present" // the table holds its chain
	guardEmpty   guardState = "empty"   // the table without the chain: a leftover no stop may leave
	guardAbsent  guardState = "absent"  // no table by that name at all
)

// ipv6Guard reads the state from one `nft list table` call, so a table
// vanishing mid-read is just absent; any other nft failure is an error
// (a poll retries it, a one-shot check fails with it).
func ipv6Guard(n *lab.Node, timeout time.Duration) (guardState, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := n.Exec(ctx, "nft", "list", "table", "inet", "thinkpol-guard")
	if err != nil {
		if strings.Contains(res.Stderr, "No such file or directory") {
			return guardAbsent, nil
		}
		return "", err
	}
	if strings.Contains(res.Stdout, "chain") {
		return guardPresent, nil
	}
	return guardEmpty, nil
}

// wantGuard returns an error unless the guard is in the wanted state.
func wantGuard(n *lab.Node, timeout time.Duration, want guardState) error {
	got, err := ipv6Guard(n, timeout)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("the IPv6 guard: %s, want %s", got, want)
	}
	return nil
}

// wantTUNGone returns nil only when the TUN is gone: only "does not exist"
// from `ip link show` counts; any other failure is an unknown state.
func wantTUNGone(n *lab.Node, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := n.Exec(ctx, "ip", "link", "show", "thinkpol0")
	if err == nil {
		return fmt.Errorf("the TUN is still there")
	}
	if !strings.Contains(res.Stderr, "does not exist") {
		return err
	}
	return nil
}

// ncConnectFailed says whether a failed `nc -v -z` run is nc's own connect
// failure: exit 1 with its "connect to ... failed" (refused, unreachable)
// or "connect to ... timed out" line. docker exec also exits 1 when docker
// fails, without that line; that and any other failure is an unknown state.
func ncConnectFailed(res lab.Result) bool {
	return res.ExitCode == 1 && strings.Contains(res.Stderr, "connect to ") &&
		(strings.Contains(res.Stderr, " failed") || strings.Contains(res.Stderr, " timed out"))
}

// pingNoReply says whether a failed ping got no reply: exit 1 and ping's
// own " 0 received" summary. Exit 2 (no route, a send error) and exec
// failures are an unknown state, never proof the path is blocked.
func pingNoReply(res lab.Result) bool {
	return res.ExitCode == 1 && strings.Contains(res.Stdout, " 0 received")
}

// pingNoAnswer says whether a failed ping shows, by ping's own account,
// that the path doesn't work: no reply (pingNoReply) or no route at the
// sender (exit 2 with the kernel's "Network is unreachable" or "No route
// to host"). Ping's other exit-2 failures are usage errors (an unknown
// interface) and say nothing.
func pingNoAnswer(res lab.Result) bool {
	out := res.Stdout + res.Stderr
	return pingNoReply(res) ||
		res.ExitCode == 2 && (strings.Contains(out, "Network is unreachable") || strings.Contains(out, "No route to host"))
}

// pingAnswers pings from n (args after "ping") and says whether a reply
// came; with what ping printed. Neither a reply nor ping's own "no"
// (pingNoAnswer) is an error: an unknown state, never a pass.
func pingAnswers(n *lab.Node, args ...string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()
	res, err := n.Exec(ctx, append([]string{"ping"}, args...)...)
	out := res.Stdout + res.Stderr
	switch {
	case err == nil:
		return true, out, nil
	case pingNoAnswer(res):
		return false, out, nil
	}
	return false, out, fmt.Errorf("ping %s on %s says nothing about the path: %w\n%s", strings.Join(args, " "), n.Name, err, out)
}

// curlNoConnection says whether a failed curl couldn't connect, by curl's
// own account: exit 7 (refused, unreachable, no route) or 28 (timed out).
// Its other failures (45: can't bind the interface) and docker's say
// nothing about the path.
func curlNoConnection(res lab.Result) bool {
	return res.ExitCode == 7 || res.ExitCode == 28
}
