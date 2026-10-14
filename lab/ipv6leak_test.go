//go:build lab

package lab_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/lab"
)

// TestNoIPv6LeavesAroundTheTunnel is TP-021's capture: while device-a is
// connected ("all but domestic", lab/maps/routetable.yaml), no IPv6
// packet leaves its physical interface but to what the rules send direct
// (the domestic site, the lab's own unique-local networks, the link
// itself) and the link to its entry: not from sockets bound to the
// interface (`ping -I`, `curl --interface`), which routing can't keep in
// the tunnel; not with the overlay too small for IPv6; not after a crash,
// until the next start removes the guard. The exit has no IPv6 uplink
// (its lab address is unique local), so tunneled IPv6 is refused there
// (TP-014): either way, it never goes around.
func TestNoIPv6LeavesAroundTheTunnel(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard().With(
		lab.NodeSpec{Name: abroad, Networks: []string{lab.NetServers}, Gateway: lab.Router},
	))
	server, dev, router, internet, far := l.Node(lab.Server1), l.Node(lab.DeviceA), l.Node(lab.Router), l.Node(lab.Internet), l.Node(abroad)
	for site, a := range map[*lab.Node]netip.Addr{internet: domestic6, far: foreign6} {
		site.MustExec(t, "ip", "addr", "add", a.String()+"/128", "dev", "lo")
		router.MustExec(t, "ip", "-6", "route", "add", a.String(), "via", site.IPv6(lab.NetServers).String())
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

	srv := server.Start(t, "thinkpol", "up", "-map-poll", "1s")
	up := dev.Start(t, "thinkpol", "up", "-map-poll", "1s")
	waitLog(t, srv, `worker space=\S+ .*`+applied(v1))
	waitLog(t, up, applied(v1)+`.*route_table_routes=`)
	waitLog(t, up, `msg="blob fetched" .*name=dm`)
	dev.MustExec(t, "thinkpol", "rules", "preset", "all-but-domestic")
	s4, _ := space.overlay(1)
	ping(t, dev, s4)

	eth := dev.Interface(lab.NetDevices)
	link6 := server.IPv6(lab.NetServers)
	// What may leave the physical side: the rules' direct set (the
	// domestic site; "local", which holds the lab's unique-local networks,
	// link-local and multicast) and the entry's endpoint.
	direct := []netip.Prefix{
		netip.MustParsePrefix("2001:db8:d0::/48"),
		netip.MustParsePrefix("fc00::/7"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
	}
	allowed := func(a netip.Addr) bool {
		for _, p := range direct {
			if p.Contains(a) {
				return true
			}
		}
		return a == link6
	}
	run := func(timeout time.Duration, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		res, err := dev.Exec(ctx, args...)
		return res.Stdout + res.Stderr, err
	}
	// attempts tries to reach the foreign site around the tunnel, every
	// way a socket can be pinned to the physical interface, and says
	// whether any got an answer.
	attempts := func(when string) {
		t.Helper()
		for _, args := range [][]string{
			{"ping", "-6", "-c", "1", "-W", "2", "-I", eth, foreign6.String()},                               // SO_BINDTODEVICE
			{"ping", "-6", "-c", "1", "-W", "2", "-I", dev.IPv6(lab.NetDevices).String(), foreign6.String()}, // the physical source address
			{"ping", "-6", "-c", "1", "-W", "2", foreign6.String()},                                          // unbound
		} {
			if out, err := run(10*time.Second, args...); err == nil {
				t.Errorf("%s: %s answered:\n%s", when, strings.Join(args, " "), out)
			}
		}
		start := time.Now()
		out, err := run(10*time.Second, "curl", "-6", "-sS", "-m", "5", "--interface", eth, "http://["+foreign6.String()+"]/")
		if err == nil {
			t.Errorf("%s: curl bound to %s reached the foreign site:\n%s", when, eth, out)
		}
		if took := time.Since(start); took > 4*time.Second {
			t.Errorf("%s: curl bound to %s took %v to fail, want refused at once: %s", when, eth, took, out)
		}
	}
	// check captures the device's own IPv6 leaving the physical side while
	// f runs: every packet is direct or to the entry, none to the foreign
	// site, and the capture saw something allowed (it works).
	check := func(when string, f func()) {
		t.Helper()
		c := dev.Capture(t, "ip6")
		f()
		// Direct traffic, so the capture provably sees the physical side.
		lab.Eventually(t, 15*time.Second, func() error {
			_, err := run(5*time.Second, "ping", "-6", "-c", "1", "-W", "2", "-I", eth, domestic6.String())
			return err
		})
		if err := c.Complete(); err != nil {
			t.Fatal(err)
		}
		seenDirect := false
		for _, p := range c.Packets() {
			if !p.Outgoing || p.Network == "" {
				continue // incoming, or the TUN
			}
			if p.Dst == domestic6 {
				seenDirect = true
			}
			if !allowed(p.Dst) {
				t.Errorf("%s: an IPv6 packet around the tunnel: %v → %v proto %d (%s)", when, p.Src, p.Dst, p.Proto, p.Network)
			}
		}
		if !seenDirect {
			t.Errorf("%s: the direct ping never showed on the physical side: the capture proves nothing", when)
		}
	}

	check("connected", func() { attempts("connected") })
	guard := func() bool {
		out, _ := run(10*time.Second, "nft", "list", "tables")
		return strings.Contains(out, "thinkpol-guard")
	}
	if !guard() {
		t.Fatal("no guard table while connected")
	}

	// The overlay too small for IPv6 (a 1300-byte link): IPv6 is
	// unreachable unbound and refused bound.
	if err := up.Stop(); err != nil {
		t.Fatalf("thinkpol up: %v\n%s", err, up.Output())
	}
	if guard() {
		t.Error("the guard outlived a clean stop")
	}
	up = dev.Start(t, "thinkpol", "up", "-map-poll", "1h", "-link-mtu", "1300")
	waitLog(t, up, applied(v1)+`.*ipv6_off=`)
	ping(t, dev, s4)
	check("IPv6 off in the overlay", func() { attempts("IPv6 off in the overlay") })

	// A crash (kill -9) while connected leaves the guard with the route
	// table: bound sockets stay confined until the next start.
	dev.MustExec(t, "pkill", "-KILL", "-f", "thinkpol up")
	<-up.Done()
	if !guard() {
		t.Fatal("the crash took the guard along")
	}
	check("after a crash", func() { attempts("after a crash") })
	up = dev.Start(t, "thinkpol", "up", "-map-poll", "1h", "-connect=false")
	waitLog(t, up, `msg=starting`)
	lab.Eventually(t, 15*time.Second, func() error {
		if guard() {
			return fmt.Errorf("the guard is still there after a start without connecting")
		}
		return nil
	})
	// Disconnected, a bound socket goes out as it would without thinkpol.
	lab.Eventually(t, 15*time.Second, func() error {
		_, err := run(5*time.Second, "ping", "-6", "-c", "1", "-W", "2", "-I", eth, foreign6.String())
		return err
	})
	if err := up.Stop(); err != nil {
		t.Errorf("thinkpol up -connect=false: %v\n%s", err, up.Output())
	}
	if err := srv.Stop(); err != nil {
		t.Errorf("server-1: %v", err)
	}
}
