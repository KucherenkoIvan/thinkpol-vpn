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
// that still sends its internet traffic to server-2.
func TestEgressThroughAnExit(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	s1, s2, devA, inet := l.Node(lab.Server1), l.Node(lab.Server2), l.Node(lab.DeviceA), l.Node(lab.Internet)
	inet4, inet6 := inet.IPv4(lab.NetServers), inet.IPv6(lab.NetServers)
	exit4, exit6 := s2.IPv4(lab.NetServers), s2.IPv6(lab.NetServers)
	space := &m0Space{builder: inet, spec: "/src/lab/maps/egress.yaml", flags: []string{"-secrets-seed", "egress-lab"}}
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
		up[name] = n.Start(t, "thinkpol", "up", "-map-poll", "1s")
	}
	uplink := regexp.QuoteMeta(s2.Interface(lab.NetServers))
	waitLog(t, up["server-2"], `msg="map applied" version=`+version1+` .*egress=on uplink=`+uplink+` egress_ipv4=on egress_ipv6=on`)
	waitLog(t, up["device-a"], applied(version1))
	// Until the route-table mode (TP-018), the device's OS routes only the
	// overlay into the TUN: route the internet node there by hand.
	devA.MustExec(t, "ip", "route", "add", inet4.String()+"/32", "dev", "thinkpol0")
	devA.MustExec(t, "ip", "-6", "route", "add", inet6.String()+"/128", "dev", "thinkpol0")

	web := inet.Capture(t, "tcp port 80")
	fetch := func(url string, timeout time.Duration) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout+5*time.Second)
		defer cancel()
		res, err := devA.Exec(ctx, "curl", "-gsS", "--max-time", fmt.Sprint(int(timeout.Seconds())), url)
		return res.Stdout + res.Stderr, err
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
	waitLog(t, up["server-2"], `msg="map applied" version=`+version2+` .*egress_ipv4=on egress_ipv6=off`)
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
	if out, err := fetch(url6, 10*time.Second); err == nil {
		t.Fatalf("IPv6 through an exit without IPv6: %q", out)
	} else if took := time.Since(start); took > 3*time.Second {
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
	settings("false", "server-3")
	v3, version3 := space.build(t)
	putMap(t, s1, v3)
	putMap(t, s2, v3)
	waitLog(t, up["server-2"], `msg="map applied" version=`+version3+` .*ingress=off egress=off`)
	waitLog(t, up["server-1"], applied(version3))
	web = inet.Capture(t, "tcp port 80 or icmp")
	for i := range 3 {
		if out, err := fetch(url4, 3*time.Second); err == nil {
			t.Fatalf("fetch %d through server-2 with its egress off: %q", i, out)
		}
	}
	server2 := netip.AddrFrom4([4]byte{100, 64, 0, 2}) // overlay addresses go in spec order
	ping(t, devA, server2)                             // the overlay through server-1 still works
	if err := web.Complete(); err != nil {
		t.Fatal(err)
	}
	if leaked := web.Stop(); len(leaked) > 0 {
		t.Fatalf("%d packets reached the internet with egress off, the first from %s", len(leaked), leaked[0].Src)
	}

	for name, p := range up {
		if err := p.Stop(); err != nil {
			t.Errorf("%s: thinkpol up exited with %v:\n%s", name, err, p.Output())
		}
	}
}
