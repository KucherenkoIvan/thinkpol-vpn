//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// What a stop (or a disconnect) must take away.

// execTimeout bounds a one-shot check's execs: the check runs once and
// fails with what it saw. pollTimeout bounds one read inside a poll: the
// poll's deadline is what bounds the wait, a read leaves it room to retry.
const (
	execTimeout = 2 * time.Minute
	pollTimeout = 10 * time.Second
)

// execRead runs one command in the node and returns its stdout; the
// error carries the failure (a poll retries it, a one-shot fails with it).
func execRead(n *lab.Node, timeout time.Duration, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := n.Exec(ctx, args...)
	if err != nil {
		return "", fmt.Errorf("%s: %v\nstdout:\n%s", strings.Join(args, " "), err, res.Stdout)
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
		return "", fmt.Errorf("nft list table inet thinkpol-guard: %v: %s", err, res.Stderr)
	}
	if strings.Contains(res.Stdout, "chain") {
		return guardPresent, nil
	}
	return guardEmpty, nil
}

// wantGuard returns an error unless the guard is in the wanted state: a
// one-shot check fails with it, a poll retries it.
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

// tunGone returns nil only when the TUN is gone: only "does not exist"
// from `ip link show` counts; any other failure is an unknown state.
func tunGone(n *lab.Node, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := n.Exec(ctx, "ip", "link", "show", "thinkpol0")
	if err == nil {
		return fmt.Errorf("the TUN is still there")
	}
	if !strings.Contains(res.Stderr, "does not exist") {
		return fmt.Errorf("ip link show thinkpol0: %v: %s", err, res.Stderr)
	}
	return nil
}
