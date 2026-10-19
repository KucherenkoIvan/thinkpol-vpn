//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// TestASecondAgentChangesNothing runs a connected device (the DNS lab
// map: route-table enforcement, the OS resolving through the node), then a
// second `thinkpol up` on the same device, connected and disconnected: the
// two starts whose cleanups (the resolv.conf restore, the route-table
// clear) would undo the running agent's. device-a's OS resolves through
// /etc/resolv.conf, device-b's through systemd-resolved. The second agent
// exits saying another one runs, without a write to resolv.conf, a change
// to resolved's links, or a routing, address or link change; the first
// one keeps working.
func TestASecondAgentChangesNothing(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	server, devA, devB, inet := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.DeviceB), l.Node(lab.Internet)
	inetIP := inet.IPv4(lab.NetServers)
	waitLog(t, inet.Start(t, "labdns", "-listen", ":53", "-a", domesticA, "-aaaa", "2001:db8:d::53"), "listening on :53/udp")
	waitLog(t, inet.Start(t, "labdns", "-listen", ":5353", "-a", foreignA, "-aaaa", foreignAAAA), "listening on :5353/udp")

	space := newM0Space(t, inet, server)
	space.spec = "/src/lab/maps/dns.yaml"
	envelope, v1 := space.build(t)
	for name, n := range map[string]*lab.Node{"server-1": server, "device-a": devA, "device-b": devB} {
		space.install(t, n, name, envelope)
	}
	s4, _ := space.overlay(1)
	exit := server.Start(t, "thinkpol", "up", "-mode", "device", "-dns-upstream", inetIP.String()+":5353")
	waitLog(t, exit, applied(v1))

	t.Run("resolv.conf", func(t *testing.T) {
		devA.WriteFile(t, "/etc/resolv.conf", []byte("nameserver "+inetIP.String()+"\noptions timeout:2 attempts:3\n"))
		secondAgentChangesNothing(t, devA, s4, nil)
	})

	t.Run("systemd-resolved", func(t *testing.T) {
		startResolved(t, devB, inetIP)
		resolved := func() string {
			return devB.MustExec(t, "sh", "-c", "resolvectl dns; resolvectl domain; resolvectl default-route thinkpol0")
		}
		secondAgentChangesNothing(t, devB, s4, resolved)
	})
}

// secondAgentChangesNothing connects n, then runs a second agent on it
// (connected, then disconnected) and checks that both are refused and that
// nothing changed: resolv.conf (its content, inode and modification time:
// a write the first agent took back shows too), the links, addresses,
// routes and rules (ip monitor, between two markers of the test's own),
// and what extra says. The first agent still reaches exit and resolves
// through the tunnel.
func secondAgentChangesNothing(t *testing.T, n *lab.Node, exit netip.Addr, extra func() string) {
	t.Helper()
	first := n.Start(t, "thinkpol", "up")
	waitLog(t, first, "the system resolves through the node")
	mustResolve(t, n, "www.tunnel.test", false, foreignA)
	ping(t, n, exit)

	state := func() string {
		s := n.MustExec(t, "sh", "-c", "stat -c '%i %y' /etc/resolv.conf; cat /etc/resolv.conf; ip rule; ip -6 rule; "+
			"ip route show table all; ip -6 route show table all; ip -br addr")
		if extra != nil {
			s += extra()
		}
		return s
	}
	const markerFrom = "from 192.0.2.99 "
	monitor := n.Start(t, "ip", "-o", "monitor", "link", "address", "route", "rule")
	// marker adds and deletes a rule of its own, waits for the monitor to
	// show both, and returns how much the monitor has said by then.
	marker := func(pref string) int {
		n.MustExec(t, "ip", "rule", "add", "pref", pref, "from", "192.0.2.99", "lookup", "main")
		n.MustExec(t, "ip", "rule", "del", "pref", pref)
		var out string
		lab.Eventually(t, 10*time.Second, func() error {
			out = monitor.Output()
			if strings.Count(out, pref+":\t"+markerFrom) < 2 && strings.Count(out, pref+": "+markerFrom) < 2 {
				return fmt.Errorf("the monitor hasn't shown marker %s yet:\n%s", pref, out)
			}
			return nil
		})
		return len(out)
	}

	before := state()
	from := marker("31998")
	for _, args := range [][]string{{"thinkpol", "up"}, {"thinkpol", "up", "-connect=false"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		res, err := n.Exec(ctx, args...)
		cancel()
		if err == nil || res.ExitCode != 1 || !strings.Contains(res.Stderr, "another thinkpol agent is running on this host") {
			t.Errorf("%s: %v (exit %d)\n%s%s", strings.Join(args, " "), err, res.ExitCode, res.Stdout, res.Stderr)
		}
	}
	to := marker("31999")
	var changes []string
	for _, line := range strings.Split(monitor.Output()[from:to], "\n") {
		if line != "" && !strings.Contains(line, markerFrom) {
			changes = append(changes, line)
		}
	}
	if len(changes) > 0 {
		t.Errorf("changed while the second agent ran:\n%s", strings.Join(changes, "\n"))
	}
	if after := state(); after != before {
		t.Errorf("the host after the second agent:\n%s\nbefore:\n%s", after, before)
	}

	if st := n.MustExec(t, "thinkpol", "status"); !regexp.MustCompile(`(?m)^state:\s+connected$`).MatchString(st) {
		t.Errorf("the first agent's status:\n%s", st)
	}
	mustResolve(t, n, "www2.tunnel.test", false, foreignA)
	ping(t, n, exit)
	if err := first.Stop(); err != nil {
		t.Errorf("the first agent: %v\n%s", err, first.Output())
	}
}
