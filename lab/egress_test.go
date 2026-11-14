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

// TestEgressThroughAnExit runs lab/maps/egress.yaml with every server in
// server mode: device-a's chain ends at server-2, relayed by server-1,
// whose worker dials server-2 out of its namespace with its own egress
// off. device-a fetches from the internet node through server-2 over IPv4
// and IPv6, and the internet sees only server-2's own addresses. Without
// an IPv6 uplink, server-2 refuses IPv6 at once (ICMPv6 no route) and
// leaks none; with its egress off, it forwards nothing while the overlay
// through it still works. device-a keeps an older map (same link secrets)
// that still sends its internet traffic to server-2. Last, server-1 and
// then server-2 are restarted with no mode set: in device mode, which
// runs no server's section, each takes no link, relays and forwards
// nothing, and leaves its host's network alone (TP-111).
func TestEgressThroughAnExit(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	s1, s2, devA, inet := l.Node(lab.Server1), l.Node(lab.Server2), l.Node(lab.DeviceA), l.Node(lab.Internet)
	inet4, exit4 := inet.IPv4(lab.NetServers), s2.IPv4(lab.NetServers)
	// The lab's IPv6 is unique local, which is no internet to an exit:
	// server-2 and the internet share a global (documentation) prefix
	// too, and server-2's IPv6 default route goes by it.
	inet6, exit6 := netip.MustParseAddr("2001:db8:5::1"), netip.MustParseAddr("2001:db8:5::2")
	inet.MustExec(t, "ip", "addr", "add", inet6.String()+"/64", "dev", inet.Interface(lab.NetServers), "nodad")
	s2.MustExec(t, "ip", "addr", "add", exit6.String()+"/64", "dev", s2.Interface(lab.NetServers), "nodad")
	s2.MustExec(t, "ip", "-6", "route", "replace", "default", "via", inet6.String(), "dev", s2.Interface(lab.NetServers))
	// The lab's networks are private, which egress and dials refuse
	// unless the node says otherwise.
	servers := netip.PrefixFrom(inet4, 24).Masked().String()
	space := &m0Space{builder: inet, spec: "/src/lab/maps/egress.yaml", flags: []string{"-insecure-secrets-seed", "egress-lab"}}
	settings := func(egress, exit string) {
		space.env = []string{
			"SERVER_1_IPV4=" + s1.IPv4(lab.NetServers).String(), "SERVER_2_IPV4=" + exit4.String(),
			"SERVER_2_EGRESS=" + egress, "EXIT=" + exit,
		}
	}
	space.builder.MustExec(t, "sh", "-ec", `mkdir -p /tmp/m0 && cd /tmp/m0
		thinkpol dev keygen space -out keys >/dev/null
		thinkpol dev keygen node -out keys server-1 server-2 server-3 device-a >/dev/null`)
	inet.MustExec(t, "sh", "-ec", "echo egress-ok > /var/www/html/index.html && nginx")

	settings("true", "server-2")
	v1, version1 := space.build(t)
	nodes := map[string]*lab.Node{"server-1": s1, "server-2": s2, "device-a": devA}
	for name, n := range nodes {
		space.install(t, n, name, v1)
	}
	up := map[string]*lab.Process{}
	for name, n := range nodes {
		up[name] = n.Start(t, upFor(name, "-map-poll", "1s", "-egress-allowed", servers)...)
	}
	uplink := regexp.QuoteMeta(s2.Interface(lab.NetServers))
	waitLog(t, up["server-2"], `msg="map applied" .*version=`+version1+` .*egress=on uplink=`+uplink+` egress_ipv4=on egress_ipv6=on`)
	waitLog(t, up["device-a"], applied(version1))
	// The device's route-table mode (TP-018) sends everything but its
	// link endpoints into the TUN: its rule is "default -> chain:out".

	web := inet.Capture(t, "tcp port 80")
	// fetch is the page at url, or an error: curl didn't connect, or said
	// nothing about the path.
	fetch := func(url string, timeout time.Duration) (string, error) {
		connected, out, err := curlFrom(devA, timeout, "-g", url)
		if err == nil && !connected {
			err = fmt.Errorf("no connection")
		}
		return out, err
	}
	// noFetch fails the test unless curl itself says it couldn't connect
	// (curlFrom); it returns what curl printed.
	noFetch := func(url string, timeout time.Duration) string {
		t.Helper()
		connected, out, err := curlFrom(devA, timeout, "-g", url)
		if err != nil {
			t.Fatal(err)
		}
		if connected {
			t.Fatalf("curl %s got through: %q", url, out)
		}
		return out
	}
	url4, url6 := "http://"+inet4.String()+"/", "http://["+inet6.String()+"]/"
	for _, url := range []string{url4, url6} {
		lab.Eventually(t, 60*time.Second, func() error {
			out, err := fetch(url, 3*time.Second)
			if err != nil || strings.TrimSpace(out) != "egress-ok" {
				return fmt.Errorf("%s: %q, %v", url, out, err)
			}
			return nil
		})
	}
	ping(t, devA, inet4)
	ping(t, devA, inet6)
	seen := web.Stop()
	from := map[netip.Addr]int{}
	for _, p := range seen {
		if !p.Outgoing && p.DstPort == 80 {
			from[p.Src]++
		}
	}
	if from[exit4] == 0 || from[exit6] == 0 || len(from) != 2 {
		t.Fatalf("the internet saw requests from %v; want only server-2's %s and %s", from, exit4, exit6)
	}

	// A VPS without IPv6: IPv6 is refused at the exit, at once, and none
	// leaves; IPv4 goes on.
	s2.MustExec(t, "ip", "-6", "route", "del", "default")
	v2, version2 := space.build(t)
	for _, n := range nodes {
		putMap(t, n, v2)
	}
	waitLog(t, up["server-2"], `msg="map applied" .*version=`+version2+` .*egress_ipv4=on egress_ipv6=off`)
	waitLog(t, up["device-a"], applied(version2))
	web = inet.Capture(t, "ip6 and tcp port 80")
	lab.Eventually(t, 30*time.Second, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		res, _ := devA.Exec(ctx, "ping", "-c", "1", "-W", "2", inet6.String())
		if !strings.Contains(res.Stdout, "Destination unreachable: No route") {
			return fmt.Errorf("ping6 through an exit without IPv6: %q", res.Stdout)
		}
		return nil
	})
	start := time.Now()
	out := noFetch(url6, 10*time.Second) // IPv6 through an exit without IPv6
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("IPv6 refused after %v, want at once: %s", took, out)
	}
	if out, err := fetch(url4, 5*time.Second); err != nil || strings.TrimSpace(out) != "egress-ok" {
		t.Fatalf("IPv4 without the IPv6 uplink: %q, %v", out, err)
	}
	if err := web.Complete(); err != nil {
		t.Fatal(err)
	}
	if leaked := web.Stop(); len(leaked) > 0 {
		t.Fatalf("%d IPv6 packets reached the internet, the first from %s", len(leaked), leaked[0].Src)
	}

	// Egress off: server-2 and server-1 take the new map, device-a keeps
	// sending its internet traffic to server-2, which forwards none of it.
	// Its engine refuses it first (the section no longer allows egress, so
	// it delivers nothing for the internet to its TUN); the namespace's and
	// the root's tables, which would refuse it next, have lab tests of their
	// own in internal/agent/supervisor.
	settings("false", "server-3")
	v3, version3 := space.build(t)
	putMap(t, s1, v3)
	putMap(t, s2, v3)
	waitLog(t, up["server-2"], `msg="map applied" .*version=`+version3+` .*ingress=off egress=off`)
	waitLog(t, up["server-1"], applied(version3))
	web = inet.Capture(t, "tcp port 80 or icmp")
	for range 3 {
		noFetch(url4, 3*time.Second) // through server-2 with its egress off
	}
	server2 := netip.AddrFrom4([4]byte{100, 64, 0, 2}) // overlay addresses go in spec order
	ping(t, devA, server2)                             // the overlay through server-1 still works
	if err := web.Complete(); err != nil {
		t.Fatal(err)
	}
	if leaked := web.Stop(); len(leaked) > 0 {
		t.Fatalf("%d packets reached the internet with egress off, the first from %s", len(leaked), leaked[0].Src)
	}

	// No mode set (TP-111): a server restarted with no -mode and no node
	// file runs in device mode, which runs no server's section. First
	// server-1, the relay device-a links to (the map makes server-2 the
	// exit again), then server-2, the exit: neither listens, so no link
	// comes up to it and nothing is relayed or forwarded; its status says
	// mode_mismatch, and its host's network stays as the server-mode run
	// left it on stopping.
	settings("true", "server-2")
	v4, version4 := space.build(t)
	for _, n := range nodes {
		putMap(t, n, v4)
	}
	waitLog(t, up["server-2"], `worker space=\S+ .*`+applied(version4))
	waitLog(t, up["device-a"], applied(version4))
	egressWorks := func() {
		t.Helper()
		lab.Eventually(t, 60*time.Second, func() error {
			out, err := fetch(url4, 3*time.Second)
			if err != nil || strings.TrimSpace(out) != "egress-ok" {
				return fmt.Errorf("%s: %q, %v", url4, out, err)
			}
			return nil
		})
	}
	egressWorks()
	netState := func(n *lab.Node) string {
		t.Helper()
		var keep []string
		for _, line := range strings.Split(n.MustExec(t, "sh", "-c", "cat /etc/resolv.conf; ip rule; ip -6 rule; "+
			"ip route show table all; ip -6 route show table all; ip -br addr; ip -br link; nft list ruleset"), "\n") {
			if !strings.Contains(line, "expires") {
				keep = append(keep, line)
			}
		}
		return strings.Join(keep, "\n")
	}
	runsNothing := func(name string, n *lab.Node) {
		t.Helper()
		if err := up[name].Stop(); err != nil {
			t.Fatalf("%s: thinkpol up exited with %v:\n%s", name, err, up[name].Output())
		}
		n.MustExec(t, "sh", "-ec", "! test -e "+stateDir+"/node.json")
		before := netState(n)
		up[name] = n.Start(t, "thinkpol", "up", "-map-poll", "1s", "-egress-allowed", servers)
		waitLog(t, up[name], `mode=device`)
		waitLog(t, up[name], `the map makes this node a server, but it runs in device mode`)
		lab.Eventually(t, 30*time.Second, func() error {
			out, err := execRead(n, pollTimeout, "thinkpol", "status")
			if err == nil && !strings.Contains(out, "mode_mismatch") {
				err = fmt.Errorf("no mode_mismatch in\n%s", out)
			}
			return err
		})
		if out := n.MustExec(t, "ss", "-Hlntu", "sport = :4500"); out != "" {
			t.Errorf("%s listens:\n%s", name, out)
		}
		noPing(t, devA, "-c", "2", "-W", "1", server2.String())
		web := inet.Capture(t, "tcp port 80 or icmp")
		for range 3 {
			noFetch(url4, 3*time.Second)
		}
		if err := web.Complete(); err != nil {
			t.Fatal(err)
		}
		if leaked := web.Stop(); len(leaked) > 0 {
			t.Fatalf("%d packets reached the internet with %s run as a device, the first from %s", len(leaked), name, leaked[0].Src)
		}
		if after := netState(n); after != before {
			t.Errorf("%s's network changed:\n%s\nwas\n%s", name, after, before)
		}
		if out := up[name].Output(); strings.Contains(out, `msg="map applied"`) || strings.Contains(out, "msg=listening") || strings.Contains(out, `msg="link up"`) {
			t.Errorf("%s ran its section:\n%s", name, out)
		}
	}
	runsNothing("server-1", s1)
	lab.Eventually(t, 30*time.Second, func() error {
		out, err := execRead(devA, pollTimeout, "thinkpol", "status")
		if err == nil && !strings.Contains(out, "no_link_up") {
			err = fmt.Errorf("device-a links:\n%s", out)
		}
		return err
	})
	if err := up["server-1"].Stop(); err != nil {
		t.Fatalf("server-1: thinkpol up exited with %v:\n%s", err, up["server-1"].Output())
	}
	up["server-1"] = s1.Start(t, upFor("server-1", "-map-poll", "1s", "-egress-allowed", servers)...)
	ping(t, devA, server2) // the relay is back
	egressWorks()
	runsNothing("server-2", s2)

	for name, p := range up {
		if err := p.Stop(); err != nil {
			t.Errorf("%s: thinkpol up exited with %v:\n%s", name, err, p.Output())
		}
	}
}
