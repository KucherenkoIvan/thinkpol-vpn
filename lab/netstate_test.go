//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// The node's network state after start, stop, connect and disconnect.

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
	res, err := execResult(n, timeout, "nft", "list", "table", "inet", "thinkpol-guard")
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
	res, err := execResult(n, timeout, "ip", "link", "show", "thinkpol0")
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

// getentNotFound says whether a failed getent found nothing, by its own
// account: exit 2, whether the resolver said so, refused or never
// answered (measured in the lab). Exit 1 is a usage error, 127 no getent;
// those and docker's failures say nothing about the name.
func getentNotFound(res lab.Result) bool { return res.ExitCode == 2 }

// tcpConnect opens and closes one TCP connection from dev to dst:port,
// waiting at most wait seconds, and says how long it took.
func tcpConnect(dev *lab.Node, dst netip.Addr, port, wait int) (lab.Result, time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(wait+10)*time.Second)
	defer cancel()
	start := time.Now()
	res, err := dev.Exec(ctx, "nc", "-v", "-z", "-w", fmt.Sprint(wait), dst.String(), fmt.Sprint(port))
	return res, time.Since(start), err
}

// tcpReaches says whether a TCP connect from n to dst:port succeeds. Only
// nc's own connect failure (ncConnectFailed) means it doesn't; any other
// failure (an exec error, a timeout, no nc) is an error.
func tcpReaches(n *lab.Node, dst netip.Addr, port, wait int) (bool, error) {
	res, _, err := tcpConnect(n, dst, port, wait)
	switch {
	case err == nil:
		return true, nil
	case ncConnectFailed(res):
		return false, nil
	}
	return false, fmt.Errorf("tcp from %s to %s: %w\n%s", n.Name, netip.AddrPortFrom(dst, uint16(port)), err, res.Stderr)
}

// pingBlackholed says whether a failed ping met a blackhole route: the
// kernel refuses the connect with EINVAL (exit 2, "connect: Invalid
// argument", measured in the lab), so nothing is sent.
func pingBlackholed(res lab.Result) bool {
	return res.ExitCode == 2 && strings.Contains(res.Stdout+res.Stderr, "connect: Invalid argument")
}

// curlNoConnection says whether a failed curl couldn't connect, by curl's
// own account: exit 7 (refused, unreachable, no route), or 28 with the
// connect phase's own text ("Connection timed out after", or "Failed to
// connect" under --connect-timeout); a 28 after connecting ("Operation
// timed out ... bytes received"), its other failures (45: can't bind the
// interface) and docker's say nothing about the path.
func curlNoConnection(res lab.Result) bool {
	out := res.Stdout + res.Stderr
	return res.ExitCode == 7 ||
		res.ExitCode == 28 && (strings.Contains(out, "Connection timed out after") || strings.Contains(out, "Failed to connect"))
}

// curlFrom runs `curl -sS` on n with args, giving up after maxTime, with
// what curl printed: true if it connected, false for curl's own
// "couldn't connect" (curlNoConnection), anything else an error (an
// unknown state, never a pass).
func curlFrom(n *lab.Node, maxTime time.Duration, args ...string) (bool, string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), maxTime+5*time.Second)
	defer cancel()
	res, err := n.Exec(ctx, append([]string{"curl", "-sS", "--max-time", fmt.Sprint(int(maxTime.Seconds()))}, args...)...)
	out := res.Stdout + res.Stderr
	switch {
	case err == nil:
		return true, out, nil
	case curlNoConnection(res):
		return false, out, nil
	}
	return false, out, fmt.Errorf("curl %s on %s says nothing about the path: %w\n%s", strings.Join(args, " "), n.Name, err, out)
}

// untilAnswer retries attempt every 300ms until it says yes or, once
// within has passed, no. An attempt's error (an unknown state, not a no)
// is retried too, and returned once no attempt has answered for 30s past
// within.
func untilAnswer(within time.Duration, attempt func() (bool, error)) (bool, error) {
	return untilAnswerOr(within, nil, attempt)
}

// untilAnswerOr is untilAnswer that also says no at once after an
// attempt that said no if watch (unless nil) says that attempt was
// blocked: watch is called just before each attempt, and what it returns
// just after one that said no.
func untilAnswerOr(within time.Duration, watch func() (blocked func() bool), attempt func() (bool, error)) (bool, error) {
	deadline := time.Now().Add(within)
	giveUp := deadline.Add(30 * time.Second)
	for {
		var blocked func() bool
		if watch != nil {
			blocked = watch()
		}
		yes, err := attempt()
		switch {
		case err == nil && yes:
			return true, nil
		case err == nil:
			if time.Now().After(deadline) || blocked != nil && blocked() {
				return false, nil
			}
		case time.Now().After(giveUp):
			return false, err
		}
		time.Sleep(300 * time.Millisecond)
	}
}
