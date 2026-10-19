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

// What a stop (or a disconnect) must take away.

// execTimeout bounds one-shot state reads, like lab's for MustExec;
// polls pass 10 s so a hung exec doesn't eat the poll's deadline.
const execTimeout = 2 * time.Minute

// policyRules is the device's policy rules (both families), which a stop
// or a failed start must put back exactly.
func policyRules(t *testing.T, n *lab.Node) (v4, v6 string) {
	t.Helper()
	return n.MustExec(t, "ip", "rule"), n.MustExec(t, "ip", "-6", "rule")
}

// routeTableRulesUp says whether the route table's own policy rules
// (priority 5301) are in both families' listings.
func routeTableRulesUp(v4, v6 string) bool {
	return strings.Contains(v4, "5301:") && strings.Contains(v6, "5301:")
}

// routeTableRoutes is everything in the routing tables of the route
// table's protocol (86), IPv4 and IPv6.
func routeTableRoutes(t *testing.T, n *lab.Node) (v4, v6 string) {
	t.Helper()
	return n.MustExec(t, "ip", "-4", "route", "show", "table", "all", "proto", "86"),
		n.MustExec(t, "ip", "-6", "route", "show", "table", "all", "proto", "86")
}

// guardState is the IPv6 leak guard's nftables table's state.
type guardState string

const (
	guardPresent guardState = "present" // the table holds its chain
	guardEmpty   guardState = "empty"   // the table without the chain: a leftover no stop may leave
	guardAbsent  guardState = "absent"  // no table by that name at all
)

// ipv6Guard reads the state from one `nft list table` call: absent only
// when nft says there is no such table, so a table vanishing mid-poll
// retries; any other failure is an error (a poll retries it, a one-shot
// check fails with it).
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
