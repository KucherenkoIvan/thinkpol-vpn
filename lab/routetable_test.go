//go:build lab

package lab_test

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

const (
	abroad  = "abroad"   // a foreign target: only through the tunnel
	router2 = "router-2" // a second gateway for the devices
)

// TestRouteTableSendsOnlyDirectAroundTheTunnel runs device-a with "all but
// domestic" (lab/maps/routetable.yaml: the internet node is domestic,
// server-1 the exit). Domestic traffic leaves in plaintext at the router;
// foreign traffic enters the TUN and never shows at the router; the link
// to server-1 bypasses the TUN; the device's gateway moves to router-2
// without a reconnect; IPv6 never goes around the tunnel, also when the
// overlay can't carry it; a stop leaves the routing as it was.
func TestRouteTableSendsOnlyDirectAroundTheTunnel(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard().With(
		lab.NodeSpec{Name: abroad, Networks: []string{lab.NetServers}, Gateway: lab.Router},
		lab.NodeSpec{Name: router2, Networks: []string{lab.NetDevices, lab.NetServers}, Forward: true},
	))
	server, dev, router, internet, far := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.Router), l.Node(lab.Internet), l.Node(abroad)
	space := newM0Space(t, internet, server)
	space.spec = "/src/lab/maps/routetable.yaml"
	space.env = append(space.env,
		"DOMESTIC_V4="+internet.IPv4(lab.NetServers).String(), "DOMESTIC_V6="+internet.IPv6(lab.NetServers).String())
	envelope, v1 := space.build(t)
	space.install(t, server, "server-1", envelope)
	space.install(t, dev, "device-a", envelope)
	rulesBefore := dev.MustExec(t, "ip", "rule") + dev.MustExec(t, "ip", "-6", "rule")
	tablesBefore := dev.MustExec(t, "sh", "-c", "ip route show table all; ip -6 route show table all")

	srv := server.Start(t, "thinkpol", "up", "-map-poll", "1s")
	up := dev.Start(t, "thinkpol", "up", "-map-poll", "1s")
	waitLog(t, srv, `worker space=\S+ .*`+applied(v1))
	waitLog(t, up, applied(v1)+`.*route_table_routes=`)
	s4, s6 := space.overlay(1)
	ping(t, dev, s4) // the overlay goes on working, through the tunnel
	ping(t, dev, s6)

	domestic4, domestic6 := internet.IPv4(lab.NetServers), internet.IPv6(lab.NetServers)
	foreign4, foreign6 := far.IPv4(lab.NetServers), far.IPv6(lab.NetServers)
	link4, link6 := server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)
	devAddrs := []netip.Addr{dev.IPv4(lab.NetDevices), dev.IPv6(lab.NetDevices)}

	// The kernel's view: unmarked packets into the TUN unless direct or an
	// endpoint, marked ones (the links' sockets) out of the physical side.
	for dst, want := range map[string]string{
		domestic4.String(): "eth", domestic6.String(): "eth",
		foreign4.String(): "thinkpol0", foreign6.String(): "thinkpol0",
		link4.String(): "eth", link6.String(): "eth",
		foreign4.String() + " mark 0x7470": "eth", foreign6.String() + " mark 0x7470": "eth",
	} {
		if got := routeDev(t, dev, dst); got != want {
			t.Errorf("route to %s: dev %s, want %s", dst, got, want)
		}
	}

	atRouter := router.Capture(t, "icmp or icmp6 or udp")
	onDevice := dev.Capture(t, "icmp or icmp6 or udp")
	// Domestic: reached directly, in plaintext at the router.
	dev.MustExec(t, "ping", "-c", "1", "-W", "2", domestic4.String())
	dev.MustExec(t, "ping", "-c", "1", "-W", "2", domestic6.String())
	// Foreign: into the TUN, through the tunnel to the exit (which drops
	// internet traffic until egress, TP-014): never out of the device in
	// plaintext.
	before := deviceCounters(t, dev)
	for _, dst := range []netip.Addr{foreign4, foreign6} {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_, _ = dev.Exec(ctx, "ping", "-c", "2", "-W", "1", dst.String())
		cancel()
	}
	ping(t, dev, s4)
	lab.Eventually(t, 10*time.Second, func() error {
		after := deviceCounters(t, dev)
		if after["router.routed"] < before["router.routed"]+4 {
			return fmt.Errorf("the router routed %d packets, want the 4 foreign pings", after["router.routed"]-before["router.routed"])
		}
		return nil
	})
	if err := atRouter.Complete(); err != nil {
		t.Fatal(err)
	}
	if err := onDevice.Complete(); err != nil {
		t.Fatal(err)
	}
	seen := func(c *lab.Capture, f func(lab.Packet) bool) int {
		n := 0
		for _, p := range c.Packets() {
			if f(p) {
				n++
			}
		}
		return n
	}
	for _, dst := range []netip.Addr{domestic4, domestic6} {
		if seen(atRouter, func(p lab.Packet) bool { return p.Dst == dst && slices.Contains(devAddrs, p.Src) }) == 0 {
			t.Errorf("the domestic ping to %s never showed at the router", dst)
		}
	}
	for _, dst := range []netip.Addr{foreign4, foreign6} {
		if n := seen(atRouter, func(p lab.Packet) bool { return p.Dst == dst }); n != 0 {
			t.Errorf("%d packets to the foreign %s at the router, want none", n, dst)
		}
		if n := seen(onDevice, func(p lab.Packet) bool { return p.Dst == dst && p.Network == "" }); n == 0 {
			t.Errorf("no packet to the foreign %s entered the TUN", dst)
		}
		if n := seen(onDevice, func(p lab.Packet) bool { return p.Dst == dst && p.Network != "" }); n != 0 {
			t.Errorf("%d packets to the foreign %s left the device outside the TUN", n, dst)
		}
	}
	if n := seen(atRouter, func(p lab.Packet) bool {
		return p.Proto == 17 && (p.Dst == link4 || p.Dst == link6) && p.DstPort == 4500
	}); n == 0 {
		t.Error("the link to server-1 never showed at the router")
	}
	if n := seen(onDevice, func(p lab.Packet) bool { return (p.Dst == link4 || p.Dst == link6) && p.Network == "" }); n != 0 {
		t.Errorf("%d packets to server-1's endpoint entered the TUN: the link loops", n)
	}
	if c := deviceCounters(t, dev); c["router.direct"] != 0 {
		t.Errorf("%d direct packets entered the TUN", c["router.direct"])
	}

	// The gateway moves (DHCP, roaming): direct traffic follows at once,
	// the tunnel keeps running without a reconnect.
	gw4, gw6 := l.Node(router2).IPv4(lab.NetDevices), l.Node(router2).IPv6(lab.NetDevices)
	reapplied := deviceCounters(t, dev)["route_table.reapplies"]
	atRouter2 := l.Node(router2).Capture(t, "icmp or icmp6")
	dev.MustExec(t, "ip", "route", "replace", "default", "via", gw4.String())
	dev.MustExec(t, "ip", "-6", "route", "replace", "default", "via", gw6.String())
	dev.MustExec(t, "ping", "-c", "1", "-W", "2", domestic4.String())
	dev.MustExec(t, "ping", "-c", "1", "-W", "2", domestic6.String())
	ping(t, dev, s4)
	ping(t, dev, s6)
	atRouter2.WaitFor(t, 5*time.Second, func(p lab.Packet) bool { return p.Dst == domestic4 && slices.Contains(devAddrs, p.Src) })
	atRouter2.WaitFor(t, 5*time.Second, func(p lab.Packet) bool { return p.Dst == domestic6 && slices.Contains(devAddrs, p.Src) })
	lab.Eventually(t, 10*time.Second, func() error {
		if deviceCounters(t, dev)["route_table.reapplies"] <= reapplied {
			return fmt.Errorf("no re-apply after the gateway change")
		}
		return nil
	})
	if strings.Contains(up.Output(), "starting the data plane") || strings.Contains(up.Output(), "applying the map failed") {
		t.Errorf("the data plane restarted or failed after the gateway change:\n%s", up.Output())
	}

	stopAndCheck := func(p *lab.Process) {
		t.Helper()
		if err := p.Stop(); err != nil {
			t.Fatalf("thinkpol up exited with %v:\n%s", err, p.Output())
		}
		after := dev.MustExec(t, "ip", "rule") + dev.MustExec(t, "ip", "-6", "rule")
		if after != rulesBefore {
			t.Errorf("rules after the stop:\n%s\nwant\n%s", after, rulesBefore)
		}
		for _, family := range []string{"-4", "-6"} {
			if out := dev.MustExec(t, "ip", family, "route", "show", "table", "all", "proto", "86"); out != "" {
				t.Errorf("route-table routes left:\n%s", out)
			}
		}
	}
	stopAndCheck(up)
	// Back on router: what the lab set up is as it was.
	dev.MustExec(t, "ip", "route", "replace", "default", "via", router.IPv4(lab.NetDevices).String())
	dev.MustExec(t, "ip", "-6", "route", "replace", "default", "via", router.IPv6(lab.NetDevices).String())
	if got := dev.MustExec(t, "sh", "-c", "ip route show table all; ip -6 route show table all"); routesOnly(got) != routesOnly(tablesBefore) {
		t.Errorf("routes after the stop:\n%s\nwant\n%s", got, tablesBefore)
	}

	// An overlay too small for IPv6 (a 1300-byte link): IPv6 is dropped,
	// not sent around the tunnel, but domestic IPv6 still goes direct.
	up = dev.Start(t, "thinkpol", "up", "-map-poll", "1h", "-link-mtu", "1300")
	waitLog(t, up, applied(v1)+`.*ipv6_off=`)
	ping(t, dev, s4)
	atRouter = router.Capture(t, "icmp6")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	res, err := dev.Exec(ctx, "ping", "-6", "-c", "1", "-W", "2", foreign6.String())
	cancel()
	if err == nil {
		t.Errorf("a foreign IPv6 ping answered with the overlay IPv4-only:\n%s", res.Stdout)
	}
	if got := routeDev(t, dev, foreign6.String()); got != "unreachable" {
		t.Errorf("route to the foreign %s with IPv6 off: %s, want unreachable", foreign6, got)
	}
	dev.MustExec(t, "ping", "-6", "-c", "1", "-W", "2", domestic6.String())
	if err := atRouter.Complete(); err != nil {
		t.Fatal(err)
	}
	if n := seen(atRouter, func(p lab.Packet) bool { return p.Dst == foreign6 }); n != 0 {
		t.Errorf("%d IPv6 packets to the foreign %s at the router with IPv6 off", n, foreign6)
	}
	stopAndCheck(up)
	if err := srv.Stop(); err != nil {
		t.Errorf("server-1: %v", err)
	}
}

// routeDev is where the device's kernel sends dst ("<addr> [mark m]"):
// "thinkpol0", "eth" for a lab interface, or "unreachable".
func routeDev(t *testing.T, n *lab.Node, dst string) string {
	t.Helper()
	args := []string{"ip", "route", "get"}
	if strings.Contains(dst, ":") {
		args = []string{"ip", "-6", "route", "get"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	res, err := n.Exec(ctx, append(args, strings.Fields(dst)...)...)
	out := res.Stdout + res.Stderr
	switch {
	case err != nil && (strings.Contains(out, "unreachable") || strings.Contains(out, "No route to host")):
		return "unreachable"
	case err != nil:
		t.Fatalf("ip route get %s: %v: %s", dst, err, out)
	case strings.Contains(out, "dev thinkpol0"):
		return "thinkpol0"
	case strings.Contains(out, "dev eth"):
		return "eth"
	}
	return out
}

var counterRE = regexp.MustCompile(`"([a-z_]+\.[a-z_]+)":\s*"?(\d+)"?`)

// deviceCounters are the device's data-plane counters, from `thinkpol
// status -json`.
func deviceCounters(t *testing.T, n *lab.Node) map[string]uint64 {
	t.Helper()
	out := n.MustExec(t, "thinkpol", "status", "-json")
	c := map[string]uint64{}
	for _, m := range counterRE.FindAllStringSubmatch(out, -1) {
		v, _ := strconv.ParseUint(m[2], 10, 64)
		c[m[1]] = v
	}
	if len(c) == 0 {
		t.Fatalf("no counters in the status:\n%s", out)
	}
	return c
}

// routesOnly drops what the kernel keeps changing on its own (expiry
// times, neighbour-learned routes) and the default routes the test moves.
func routesOnly(s string) string {
	var out []string
	for _, line := range strings.Split(s, "\n") {
		if strings.Contains(line, "expires") || strings.Contains(line, "proto ra") || strings.HasPrefix(line, "default") {
			continue
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
