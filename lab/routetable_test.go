//go:build lab

package lab_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	abroad  = "abroad"   // a foreign site: only through the tunnel
	router2 = "router-2" // a second gateway for the devices
)

// The sites' public addresses: the lab's networks are private ranges,
// which every preset sends direct (`local`), so the sites get addresses
// of their own on lo, routed by both routers.
var (
	domestic4, domestic6 = netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("2001:db8:d0::7")
	foreign4, foreign6   = netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8:ab::7")
)

// domesticList is the space's domestic list (DB-IP CSV form): the
// domestic site's networks.
const domesticList = "198.51.100.0,198.51.100.255,DM\n2001:db8:d0::,2001:db8:d0:ffff:ffff:ffff:ffff:ffff,DM\n"

// TestRouteTableSendsOnlyDirectAroundTheTunnel runs device-a with the
// "all but domestic" preset (lab/maps/routetable.yaml; its list reaches the
// device through the overlay from server-1, the chain's exit). Domestic
// traffic leaves in plaintext at the router; foreign traffic enters the
// TUN and never shows at the router; the link to server-1 bypasses the
// TUN; the device's gateway moves to router-2 without a reconnect;
// switching presets moves the domestic site into the tunnel and back;
// IPv6 never goes around the tunnel, also when the overlay can't carry
// it; a stop leaves the routing as it was.
func TestRouteTableSendsOnlyDirectAroundTheTunnel(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard().With(
		lab.NodeSpec{Name: abroad, Networks: []string{lab.NetServers}, Gateway: lab.Router},
		lab.NodeSpec{Name: router2, Networks: []string{lab.NetDevices, lab.NetServers}, Forward: true},
	))
	server, dev, router, internet, far := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.Router), l.Node(lab.Internet), l.Node(abroad)
	for site, addrs := range map[*lab.Node][2]netip.Addr{internet: {domestic4, domestic6}, far: {foreign4, foreign6}} {
		site.MustExec(t, "ip", "addr", "add", addrs[0].String()+"/32", "dev", "lo")
		site.MustExec(t, "ip", "addr", "add", addrs[1].String()+"/128", "dev", "lo")
		for _, r := range []*lab.Node{router, l.Node(router2)} {
			r.MustExec(t, "ip", "route", "add", addrs[0].String(), "via", site.IPv4(lab.NetServers).String())
			r.MustExec(t, "ip", "-6", "route", "add", addrs[1].String(), "via", site.IPv6(lab.NetServers).String())
		}
	}

	space := newM0Space(t, internet, server)
	space.spec = "/src/lab/maps/routetable.yaml"
	space.env = append(space.env, "DM_LIST=/tmp/m0/lists/dm.geoip")
	internet.WriteFile(t, "/tmp/m0/domestic.csv", []byte(domesticList))
	internet.MustExec(t, "sh", "-ec", "cd /tmp/m0 && thinkpol dev lists build -only dm -out lists domestic.csv >/dev/null")
	envelope, v1 := space.build(t)
	space.install(t, server, "server-1", envelope)
	space.install(t, dev, "device-a", envelope)
	list := space.file(t, "lists/dm.geoip")
	sum := sha256.Sum256(list)
	seed := stateDir + "/blobs/" + hex.EncodeToString(sum[:])
	server.MustExec(t, "install", "-d", "-m", "700", stateDir+"/blobs")
	server.WriteFile(t, seed, list)
	server.MustExec(t, "chmod", "600", seed)
	rulesBefore4, rulesBefore6, err := policyRules(dev, execTimeout)
	if err != nil {
		t.Fatal(err)
	}
	tablesBefore := dev.MustExec(t, "sh", "-c", "ip route show table all; ip -6 route show table all")

	srv := server.Start(t, "thinkpol", "up", "-map-poll", "1s")
	up := dev.Start(t, "thinkpol", "up", "-map-poll", "1s")
	waitLog(t, srv, `worker space=\S+ .*`+applied(v1))
	waitLog(t, up, applied(v1)+`.*route_table_routes=`)
	waitLog(t, up, `msg="blob fetched" .*name=dm`)
	s4, s6 := space.overlay(1)
	ping(t, dev, s4) // the overlay goes on working, through the tunnel
	ping(t, dev, s6)
	preset := func(name string) {
		t.Helper()
		dev.MustExec(t, "thinkpol", "rules", "preset", name)
	}
	preset("all-but-domestic")

	link4, link6 := server.IPv4(lab.NetServers), server.IPv6(lab.NetServers)
	devAddrs := []netip.Addr{dev.IPv4(lab.NetDevices), dev.IPv6(lab.NetDevices)}
	// routeNow and countersNow are one-shot reads: they fail the test at
	// once. Polls call routeDev and deviceCounters with pollTimeout instead.
	routeNow := func(dst string) string {
		t.Helper()
		got, err := routeDev(dev, execTimeout, dst)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	countersNow := func() map[string]uint64 {
		t.Helper()
		c, err := deviceCounters(dev, execTimeout)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	// The kernel's view: unmarked packets into the TUN unless direct or an
	// endpoint, marked ones (the links' sockets) out of the physical side.
	expectRoutes := func(want map[string]string) {
		t.Helper()
		for dst, w := range want {
			if got := routeNow(dst); got != w {
				t.Errorf("route to %s: dev %s, want %s", dst, got, w)
			}
		}
	}
	expectRoutes(map[string]string{
		domestic4.String(): "eth", domestic6.String(): "eth",
		foreign4.String(): "thinkpol0", foreign6.String(): "thinkpol0",
		link4.String(): "eth", link6.String(): "eth",
		foreign4.String() + " mark 0x7470": "eth", foreign6.String() + " mark 0x7470": "eth",
	})

	seen := func(c *lab.Capture, f func(lab.Packet) bool) int {
		n := 0
		for _, p := range c.Packets() {
			if f(p) {
				n++
			}
		}
		return n
	}
	// tryPing pings without caring for an answer: the exit forwards IPv4
	// (TP-014), but has no IPv6 uplink (its lab address is unique local).
	tryPing := func(dst netip.Addr) {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = dev.Exec(ctx, "ping", "-c", "2", "-W", "1", dst.String())
	}
	atRouter := router.Capture(t, "icmp or icmp6 or udp")
	onDevice := dev.Capture(t, "icmp or icmp6 or udp")
	// Domestic: reached directly, in plaintext at the router.
	dev.MustExec(t, "ping", "-c", "1", "-W", "2", domestic4.String())
	dev.MustExec(t, "ping", "-c", "1", "-W", "2", domestic6.String())
	// Foreign: into the TUN, through the tunnel to the exit: never out of
	// the device in plaintext.
	before := countersNow()
	tryPing(foreign4)
	tryPing(foreign6)
	ping(t, dev, s4)
	lab.Eventually(t, 10*time.Second, func() error {
		after, err := deviceCounters(dev, pollTimeout)
		if err != nil {
			return err
		}
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
	for _, dst := range []netip.Addr{domestic4, domestic6} {
		if seen(atRouter, func(p lab.Packet) bool { return p.Dst == dst && slices.Contains(devAddrs, p.Src) }) == 0 {
			t.Errorf("the domestic ping to %s never showed at the router", dst)
		}
	}
	for _, dst := range []netip.Addr{foreign4, foreign6} {
		// The exit's forwarded copies cross the router too, from its own
		// address: none may come from the device's.
		if n := seen(atRouter, func(p lab.Packet) bool { return p.Dst == dst && slices.Contains(devAddrs, p.Src) }); n != 0 {
			t.Errorf("%d packets from the device to the foreign %s at the router, want none", n, dst)
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
	// Nothing direct enters the TUN. (The router's direct counter isn't the
	// measure: the TUN's own link-local multicast, MLD and router
	// solicitations, is "local" and counted there.)
	for _, dst := range []netip.Addr{domestic4, domestic6} {
		if n := seen(onDevice, func(p lab.Packet) bool { return p.Dst == dst && p.Network == "" }); n != 0 {
			t.Errorf("%d packets to the domestic %s entered the TUN", n, dst)
		}
	}

	// The gateway moves (DHCP, roaming): direct traffic follows at once,
	// the tunnel keeps running without a reconnect.
	gw4, gw6 := l.Node(router2).IPv4(lab.NetDevices), l.Node(router2).IPv6(lab.NetDevices)
	reapplied := countersNow()["route_table.reapplies"]
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
		c, err := deviceCounters(dev, pollTimeout)
		if err != nil {
			return err
		}
		if c["route_table.reapplies"] <= reapplied {
			return fmt.Errorf("no re-apply after the gateway change")
		}
		return nil
	})
	if strings.Contains(up.Output(), "starting the data plane") || strings.Contains(up.Output(), "applying the map failed") {
		t.Errorf("the data plane restarted or failed after the gateway change:\n%s", up.Output())
	}

	// "Everything": the domestic site goes through the tunnel too, and
	// never shows at a router; back to "all but domestic", it is direct
	// again.
	preset("everything")
	expectRoutes(map[string]string{domestic4.String(): "thinkpol0", domestic6.String(): "thinkpol0", "192.168.7.7": "eth"})
	atRouter2 = l.Node(router2).Capture(t, "icmp or icmp6")
	tryPing(domestic4)
	tryPing(domestic6)
	if err := atRouter2.Complete(); err != nil {
		t.Fatal(err)
	}
	if n := seen(atRouter2, func(p lab.Packet) bool { return p.Dst == domestic4 || p.Dst == domestic6 }); n != 0 {
		t.Errorf("%d packets to the domestic site outside the tunnel with everything tunneled", n)
	}
	preset("all-but-domestic")
	dev.MustExec(t, "ping", "-c", "1", "-W", "2", domestic4.String())

	// TunnelVision (CVE-2024-3661): routes in the main table that are more
	// specific than its default (a DHCP server's classless routes, another
	// VPN's split defaults) don't take foreign traffic around the tunnel.
	// Then the TUN goes down and up: its IPv4 default goes with it without
	// a word from the kernel, the re-apply puts the unreachable default in
	// its place, and the route table is put back once the TUN is up.
	gw := l.Node(router2).IPv4(lab.NetDevices).String()
	atGateway := l.Node(router2).Capture(t, "icmp or icmp6") // the device's gateway by now
	dev.MustExec(t, "ip", "route", "add", "0.0.0.0/1", "via", gw)
	dev.MustExec(t, "ip", "route", "add", "128.0.0.0/1", "via", gw)
	expectRoutes(map[string]string{foreign4.String(): "thinkpol0", domestic4.String(): "eth"})
	tryPing(foreign4)
	dev.MustExec(t, "ip", "route", "del", "0.0.0.0/1")
	dev.MustExec(t, "ip", "route", "del", "128.0.0.0/1")
	// IPv4's unreachable default follows the link event a debounce later
	// (TP-057: always there, it would refuse the gateways of interfaces
	// added meanwhile); the status says the TUN is down.
	dev.MustExec(t, "ip", "link", "set", "thinkpol0", "down")
	lab.Eventually(t, 15*time.Second, func() error {
		st, err := execRead(dev, pollTimeout, "thinkpol", "status")
		if err != nil {
			return err
		}
		if !strings.Contains(st, "route_table_not_enforced") {
			return fmt.Errorf("the status doesn't say the route table isn't enforced")
		}
		return nil
	})
	expectRoutes(map[string]string{foreign4.String(): "unreachable"})
	tryPing(foreign4)
	dev.MustExec(t, "ip", "link", "set", "thinkpol0", "up")
	lab.Eventually(t, 15*time.Second, func() error {
		got, err := routeDev(dev, pollTimeout, foreign4.String())
		if err != nil {
			return err
		}
		if got != "thinkpol0" {
			return fmt.Errorf("foreign IPv4 goes %s after the TUN came up", got)
		}
		return nil
	})
	tryPing(foreign4)
	if err := atGateway.Complete(); err != nil {
		t.Fatal(err)
	}
	if n := seen(atGateway, func(p lab.Packet) bool { return p.Dst == foreign4 && slices.Contains(devAddrs, p.Src) }); n != 0 {
		t.Errorf("%d packets to the foreign %s at the router with split routes in main or the TUN down", n, foreign4)
	}

	stopAndCheck := func(p *lab.Process) {
		t.Helper()
		if err := p.Stop(); err != nil {
			t.Fatalf("thinkpol up exited with %v:\n%s", err, p.Output())
		}
		after4, after6, err := policyRules(dev, execTimeout)
		if err != nil {
			t.Fatal(err)
		}
		if after4 != rulesBefore4 || after6 != rulesBefore6 {
			t.Errorf("rules after the stop:\n%s\n%s\nwant\n%s\n%s", after4, after6, rulesBefore4, rulesBefore6)
		}
		v4, v6, err := routeTableRoutes(dev, execTimeout)
		if err != nil {
			t.Fatal(err)
		}
		if v4 != "" || v6 != "" {
			t.Errorf("route-table routes left:\n%s\n%s", v4, v6)
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
	// The preset and the list are the device's from before.
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
	if got := routeNow(foreign6.String()); got != "unreachable" {
		t.Errorf("route to the foreign %s with IPv6 off: %s, want unreachable", foreign6, got)
	}
	// A specific IPv6 route in main (a router advertisement's route
	// information) doesn't take IPv6 around the tunnel either.
	dev.MustExec(t, "ip", "-6", "route", "add", "2000::/3", "via", router.IPv6(lab.NetDevices).String())
	if got := routeNow(foreign6.String()); got != "unreachable" {
		t.Errorf("route to the foreign %s with IPv6 off and 2000::/3 in main: %s, want unreachable", foreign6, got)
	}
	tryPing(foreign6)
	dev.MustExec(t, "ip", "-6", "route", "del", "2000::/3")
	lab.Eventually(t, 30*time.Second, func() error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := dev.Exec(ctx, "ping", "-6", "-c", "1", "-W", "2", domestic6.String())
		return err
	})
	if err := atRouter.Complete(); err != nil {
		t.Fatal(err)
	}
	if n := seen(atRouter, func(p lab.Packet) bool { return p.Dst == foreign6 }); n != 0 {
		t.Errorf("%d IPv6 packets to the foreign %s at the router with IPv6 off", n, foreign6)
	}

	// A crash (kill -9) while connected leaves the rules and the table;
	// a restart that doesn't connect removes them.
	dev.MustExec(t, "pkill", "-KILL", "-f", "thinkpol up")
	<-up.Done()
	if rules4, rules6, err := policyRules(dev, execTimeout); err != nil {
		t.Fatal(err)
	} else if !routeTableRulesUp(rules4, rules6) {
		t.Fatal("no rules left by the crash: the test proves nothing")
	}
	up = dev.Start(t, "thinkpol", "up", "-map-poll", "1h", "-connect=false")
	waitLog(t, up, `msg=starting`)
	lab.Eventually(t, 15*time.Second, func() error {
		v4, v6, err := policyRules(dev, pollTimeout)
		if err != nil {
			return err
		}
		if v4 != rulesBefore4 || v6 != rulesBefore6 {
			return fmt.Errorf("rules after a restart without connecting:\n%s\n%s", v4, v6)
		}
		return nil
	})
	stopAndCheck(up)

	// A crash while connected, then a start that fails before the route
	// table is taken over (no TUN): the leftovers go anyway, rather than
	// keep the device's traffic blocked while it fails.
	up = dev.Start(t, "thinkpol", "up", "-map-poll", "1h")
	waitLog(t, up, applied(v1))
	dev.MustExec(t, "pkill", "-KILL", "-f", "thinkpol up")
	<-up.Done()
	if rules4, rules6, err := policyRules(dev, execTimeout); err != nil {
		t.Fatal(err)
	} else if !routeTableRulesUp(rules4, rules6) {
		t.Fatal("no rules left by the second crash: the test proves nothing")
	}
	// eth0 exists and isn't a TUN: creating the TUN fails at run time.
	failing := dev.Start(t, "thinkpol", "up", "-map-poll", "1h", "-interface", dev.Interface(lab.NetDevices))
	<-failing.Done()
	if failing.Err() == nil || !strings.Contains(failing.Output(), "tun") {
		t.Fatalf("thinkpol up didn't fail at the TUN: %v\n%s", failing.Err(), failing.Output())
	}
	if v4, v6, err := policyRules(dev, execTimeout); err != nil {
		t.Fatal(err)
	} else if v4 != rulesBefore4 || v6 != rulesBefore6 {
		t.Errorf("rules after a crash and a failed start:\n%s\n%s\nwant\n%s\n%s\n%s", v4, v6, rulesBefore4, rulesBefore6, failing.Output())
	}
	if v4, v6, err := routeTableRoutes(dev, execTimeout); err != nil {
		t.Fatal(err)
	} else if v4 != "" || v6 != "" {
		t.Errorf("route-table routes left after a failed start:\n%s\n%s", v4, v6)
	}
	if err := srv.Stop(); err != nil {
		t.Errorf("server-1: %v", err)
	}
}

// routeDev is where the device's kernel sends dst ("<addr> [mark m]"):
// "thinkpol0", "eth" for a lab interface, or "unreachable".
func routeDev(n *lab.Node, timeout time.Duration, dst string) (string, error) {
	args := []string{"ip", "route", "get"}
	if strings.Contains(dst, ":") {
		args = []string{"ip", "-6", "route", "get"}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	res, err := n.Exec(ctx, append(args, strings.Fields(dst)...)...)
	out := res.Stdout + res.Stderr
	switch {
	case err != nil && (strings.Contains(out, "unreachable") || strings.Contains(out, "No route to host")):
		return "unreachable", nil
	case err != nil:
		return "", fmt.Errorf("ip route get %s: %w: %s", dst, err, out)
	case strings.Contains(out, "dev thinkpol0"):
		return "thinkpol0", nil
	case strings.Contains(out, "dev eth"):
		return "eth", nil
	}
	return out, nil
}

var counterRE = regexp.MustCompile(`"([a-z_]+\.[a-z_]+)":\s*"?(\d+)"?`)

// deviceCounters are the device's data-plane counters, from `thinkpol
// status -json`.
func deviceCounters(n *lab.Node, timeout time.Duration) (map[string]uint64, error) {
	out, err := execRead(n, timeout, "thinkpol", "status", "-json")
	if err != nil {
		return nil, err
	}
	c := map[string]uint64{}
	for _, m := range counterRE.FindAllStringSubmatch(out, -1) {
		v, _ := strconv.ParseUint(m[2], 10, 64)
		c[m[1]] = v
	}
	if len(c) == 0 {
		return nil, fmt.Errorf("no counters in the status:\n%s", out)
	}
	return c, nil
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
