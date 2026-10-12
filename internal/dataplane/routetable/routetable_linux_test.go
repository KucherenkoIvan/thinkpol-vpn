//go:build linux && !android

package routetable_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// device is a network namespace set up like a device: a "physical" eth0
// with default routes for both families and a TUN-like thinkpol0 with the
// overlay's addresses.
type device struct{ name string }

func newDevice(t *testing.T) *device {
	t.Helper()
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	d := &device{name: "rt-" + hex.EncodeToString(b)}
	if out, err := exec.Command("ip", "netns", "add", d.name).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v: %s", err, out)
	}
	t.Cleanup(func() { _, _ = exec.Command("ip", "netns", "del", d.name).CombinedOutput() })
	for _, args := range [][]string{
		{"link", "add", "eth0", "type", "dummy"},
		{"link", "add", "thinkpol0", "type", "dummy"},
		{"link", "set", "lo", "up"},
		{"link", "set", "eth0", "up"},
		{"link", "set", "thinkpol0", "up"},
		{"addr", "add", "192.0.2.2/24", "dev", "eth0"},
		{"addr", "add", "2001:db8:1::2/64", "dev", "eth0", "nodad"},
		{"addr", "add", "100.64.0.2/10", "dev", "thinkpol0"},
		{"addr", "add", "fd12:3456:789a::2/48", "dev", "thinkpol0", "nodad"},
		{"route", "add", "default", "via", "192.0.2.1"},
		{"-6", "route", "add", "default", "via", "2001:db8:1::1"},
	} {
		d.ip(t, args...)
	}
	return d
}

func (d *device) ip(t *testing.T, args ...string) string {
	t.Helper()
	out, err := d.tryIP(args...)
	if err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return out
}

func (d *device) tryIP(args ...string) (string, error) {
	out, err := exec.Command("ip", append([]string{"-n", d.name}, args...)...).CombinedOutput()
	return string(out), err
}

func (d *device) enforcer(t *testing.T) *routetable.Enforcer {
	t.Helper()
	c, err := netcfg.NewInNamespace("/run/netns/"+d.name, netcfg.OwnerRouteTable)
	if err != nil {
		t.Fatal(err)
	}
	e := routetable.Open(c, nil)
	t.Cleanup(func() { _ = e.Close() })
	return e
}

// route says where the kernel sends a packet: "tunnel", "via <gateway>",
// "unreachable", or what ip printed.
func (d *device) route(t *testing.T, dst string, mark bool) string {
	t.Helper()
	args := []string{"route", "get", dst}
	if strings.Contains(dst, ":") {
		args = append([]string{"-6"}, args...)
	}
	if mark {
		args = append(args, "mark", "0x7470")
	}
	out, err := d.tryIP(args...)
	switch {
	case err != nil && (strings.Contains(out, "unreachable") || strings.Contains(out, "No route to host")):
		return "unreachable"
	case err != nil:
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
	f := strings.Fields(out)
	for i := range f[:max(len(f)-1, 0)] {
		if f[i] == "via" {
			return "via " + f[i+1]
		}
	}
	switch {
	case strings.Contains(out, "dev thinkpol0"):
		return "tunnel"
	case strings.Contains(out, "dev eth0"):
		return "on-link"
	}
	return out
}

func (d *device) expect(t *testing.T, cases map[string]string) {
	t.Helper()
	for dst, want := range cases {
		mark := strings.HasSuffix(dst, " marked")
		if got := d.route(t, strings.TrimSuffix(dst, " marked"), mark); got != want {
			t.Errorf("%s: %s, want %s\nrules:\n%smain:\n%s", dst, got, want, d.ip(t, "rule"), d.ip(t, "route"))
		}
	}
}

// state is what route-table enforcement can leave: its table and every
// rule.
func (d *device) state(t *testing.T) string {
	t.Helper()
	return d.ip(t, "rule") + d.ip(t, "-6", "rule") + d.ip(t, "route", "show", "table", "all", "proto", "86") +
		d.ip(t, "-6", "route", "show", "table", "all", "proto", "86")
}

func local() *lists.Set { return lists.Local() }

func TestEnforcesInANamespace(t *testing.T) {
	d := newDevice(t)
	before := d.state(t)
	e := d.enforcer(t)
	ctx := context.Background()
	var b lists.Builder
	b.AddSet(local())
	_ = b.AddPrefix(netip.MustParsePrefix("198.51.100.0/24"))
	_ = b.AddPrefix(netip.MustParsePrefix("2001:db8:5::/48"))
	var ob lists.Builder
	_ = ob.AddPrefix(netip.MustParsePrefix("100.64.0.0/10"))
	_ = ob.AddPrefix(netip.MustParsePrefix("fd12:3456:789a::/48"))
	overlay, _ := ob.Build()
	direct, _ := b.Build()
	direct = direct.Minus(overlay) // the overlay is decided before any rule
	want := routetable.Want{
		TUN:     "thinkpol0",
		Overlay: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd12:3456:789a::/48")},
		Direct:  direct,
		Bypass:  []netip.Addr{netip.MustParseAddr("203.0.113.7"), netip.MustParseAddr("2001:db8:7::7")},
		IPv6:    true,
	}
	if err := e.Enforce(ctx, want); err != nil {
		t.Fatal(err)
	}
	d.expect(t, map[string]string{
		"198.51.100.9":        "via 192.0.2.1",     // direct
		"8.8.8.8":             "tunnel",            // everything else
		"8.8.8.8 marked":      "via 192.0.2.1",     // a link's socket
		"203.0.113.7":         "via 192.0.2.1",     // an endpoint, even unmarked
		"100.64.0.9":          "tunnel",            // the overlay, by its own route
		"192.0.2.77":          "tunnel",            // a public LAN: never trusted on-link
		"2001:4860::8888":     "tunnel",            // IPv6 too
		"2001:db8:5::1":       "via 2001:db8:1::1", // direct IPv6
		"2001:db8:7::7":       "via 2001:db8:1::1", // an IPv6 endpoint
		"fd12:3456:789a::9":   "tunnel",            // the overlay's IPv6
		"2001:4860::1 marked": "via 2001:db8:1::1", // a marked IPv6 socket
	})

	// The gateway moves (DHCP, roaming): direct traffic follows without
	// a change here; the watcher re-applies, finding nothing to do.
	table := d.state(t)
	d.ip(t, "route", "replace", "default", "via", "192.0.2.3", "dev", "eth0") // as DHCP clients add it
	d.ip(t, "-6", "route", "replace", "default", "via", "2001:db8:1::3")
	if out := d.ip(t, "route", "show", "default"); !strings.Contains(out, "dev eth0") {
		t.Errorf("the new default route resolved its gateway into the tunnel: %s", out)
	}
	d.expect(t, map[string]string{
		"198.51.100.9":   "via 192.0.2.3",
		"8.8.8.8":        "tunnel",
		"8.8.8.8 marked": "via 192.0.2.3",
		"2001:db8:5::1":  "via 2001:db8:1::3",
	})
	waitFor(t, func() bool { return e.Status().Reapplies > 0 }, "a re-Apply after the gateway changed")
	if got := d.state(t); got != table {
		t.Errorf("the gateway change changed the table:\n%s\nwant\n%s", got, table)
	}

	// Someone deletes our rule and a route: put back without an Enforce.
	d.ip(t, "rule", "del", "priority", "5301")
	d.ip(t, "route", "del", "throw", "198.51.100.0/24", "table", "29808")
	waitFor(t, func() bool { return d.state(t) == table }, "the rule and route put back")

	// TunnelVision (CVE-2024-3661): a DHCP server's classless routes, or
	// another VPN's split defaults, in the main table don't beat the
	// tunnel; neither does an "on-link" subnet from a huge netmask.
	d.ip(t, "route", "add", "0.0.0.0/1", "via", "192.0.2.1")
	d.ip(t, "route", "add", "128.0.0.0/1", "via", "192.0.2.1")
	d.ip(t, "addr", "add", "8.8.4.4/8", "dev", "eth0")
	reapplies := e.Status().Reapplies
	waitFor(t, func() bool { return e.Status().Reapplies > reapplies }, "a re-Apply after the new address")
	d.expect(t, map[string]string{"8.8.8.8": "tunnel", "100.64.0.9": "tunnel", "192.0.2.77": "tunnel", "198.51.100.9": "via 192.0.2.1"})
	d.ip(t, "addr", "del", "8.8.4.4/8", "dev", "eth0")
	d.ip(t, "route", "del", "0.0.0.0/1")
	d.ip(t, "route", "del", "128.0.0.0/1")

	// The TUN goes down: its routes go with it, silently for IPv4, and
	// the unreachable defaults keep everything in; the route table says
	// it isn't enforced until the TUN is up and its default is back.
	d.ip(t, "link", "set", "thinkpol0", "down")
	d.expect(t, map[string]string{"8.8.8.8": "unreachable", "2001:4860::8888": "unreachable", "198.51.100.9": "via 192.0.2.3"})
	waitFor(t, func() bool { st := e.Status(); return !st.Enforced && st.Error == routetable.ErrorReapply }, "the status saying it isn't enforced")
	d.ip(t, "link", "set", "thinkpol0", "up")
	waitFor(t, func() bool { return e.Status().Enforced }, "enforcement back after the TUN came up")
	d.expect(t, map[string]string{"8.8.8.8": "tunnel", "2001:4860::8888": "tunnel"})

	// The overlay stops carrying IPv6: IPv6 is unreachable, not leaked,
	// but direct IPv6 and endpoints still go out.
	want.IPv6 = false
	if err := e.Enforce(ctx, want); err != nil {
		t.Fatal(err)
	}
	// A specific IPv6 route in main (a router advertisement's route
	// information) doesn't beat it either.
	d.ip(t, "-6", "route", "add", "2000::/3", "via", "2001:db8:1::1")
	d.expect(t, map[string]string{
		"2001:4860::8888":   "unreachable",
		"fd12:3456:789a::9": "unreachable",       // the TUN lost its IPv6 address going down: no route of its own
		"2001:db8:5::1":     "via 2001:db8:1::1", // direct, by main's routes, the injected one included
		"2001:db8:7::7":     "via 2001:db8:1::1",
		"8.8.8.8":           "tunnel",
	})
	d.ip(t, "-6", "route", "del", "2000::/3")
	// IPv6 going off on the TUN itself (an MTU below 1280) takes its
	// route along: still unreachable.
	want.IPv6 = true
	if err := e.Enforce(ctx, want); err != nil {
		t.Fatal(err)
	}
	d.ip(t, "link", "set", "thinkpol0", "mtu", "1200")
	d.expect(t, map[string]string{"2001:4860::8888": "unreachable"})

	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if got := d.state(t); got != before {
		t.Errorf("after Close:\n%s\nwant\n%s", got, before)
	}
	d.expect(t, map[string]string{"8.8.8.8": "via 192.0.2.3"})
}

func waitFor(t *testing.T, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// countrySized is a direct set the size of RU's (TP-016: 12,895 IPv4 and
// 10,088 IPv6 prefixes), none of them mergeable.
func countrySized(t testing.TB) *lists.Set {
	t.Helper()
	var b lists.Builder
	for i := range 12895 {
		n := uint32(0x05000000) + uint32(i)*512 // every other /24 from 5.0.0.0
		_ = b.AddPrefix(netip.PrefixFrom(netip.AddrFrom4([4]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), 0}), 24))
	}
	for i := range 10088 {
		n := uint32(0x2a000000) + uint32(i)*2 // every other /32 from 2a00::
		_ = b.AddPrefix(netip.PrefixFrom(netip.AddrFrom16([16]byte{byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}), 32))
	}
	b.AddSet(local())
	s, st := b.Build()
	if st.Prefixes4+st.Prefixes6 < 22983 {
		t.Fatalf("the set has %d prefixes", st.Prefixes4+st.Prefixes6)
	}
	return s
}

func TestCountrySizedTable(t *testing.T) {
	d := newDevice(t)
	before := d.state(t)
	e := d.enforcer(t)
	ctx := context.Background()
	ru := routetable.Want{TUN: "thinkpol0", Direct: countrySized(t), IPv6: true,
		Bypass: []netip.Addr{netip.MustParseAddr("203.0.113.7")}}
	timed := func(what string, f func() error) time.Duration {
		t.Helper()
		start := time.Now()
		if err := f(); err != nil {
			t.Fatalf("%s: %v", what, err)
		}
		took := time.Since(start)
		t.Logf("%s: %v", what, took.Round(time.Millisecond))
		// Generous: a laptop does this in about a second; the bound only
		// catches something quadratic.
		if took > 20*time.Second {
			t.Errorf("%s took %v", what, took)
		}
		return took
	}
	timed("connect, all but domestic (first Apply)", func() error { return e.Enforce(ctx, ru) })
	t.Logf("routes in the table: %d", e.Status().Routes)
	d.expect(t, map[string]string{"5.0.2.9": "via 192.0.2.1", "5.0.1.9": "tunnel", "2a00:2::1": "via 2001:db8:1::1", "2a00:1::1": "tunnel"})

	// A map that moves an endpoint: one route changes, the rest is a dump
	// and a diff.
	moved := ru
	moved.Bypass = []netip.Addr{netip.MustParseAddr("203.0.113.8")}
	timed("re-Apply with one endpoint moved", func() error { return e.Enforce(ctx, moved) })

	// A gateway change: nothing to do but the watcher's no-op re-Apply.
	reapplies := e.Status().Reapplies
	d.ip(t, "route", "replace", "default", "via", "192.0.2.3")
	waitFor(t, func() bool { return e.Status().Reapplies > reapplies }, "the re-Apply after the gateway change")
	d.expect(t, map[string]string{"5.0.2.9": "via 192.0.2.3", "5.0.1.9": "tunnel"})

	everything := moved
	everything.Direct = local()
	timed("switch to everything (removes the country)", func() error { return e.Enforce(ctx, everything) })
	d.expect(t, map[string]string{"5.0.2.9": "tunnel"})
	timed("switch back to all but domestic", func() error { return e.Enforce(ctx, moved) })
	timed("disconnect (Close)", e.Close)
	if got := d.state(t); got != before {
		t.Errorf("after Close:\n%s\nwant\n%s", got, before)
	}
}

// What a hostile local network can plant takes nothing around the tunnel:
// a public subnet made on-link by a DHCP address or a router
// advertisement (TunnelCrack's LocalNet), and routes into the overlay's
// range (a classless route, an address inside it, an advertised prefix
// inside the overlay's /48: TunnelVision on the overlay).
func TestHostileLocalNetworkRoutes(t *testing.T) {
	d := newDevice(t)
	e := d.enforcer(t)
	overlay := []netip.Prefix{netip.MustParsePrefix("100.64.0.0/16"), netip.MustParsePrefix("fd12:3456:789a::/48")}
	var ob lists.Builder
	for _, p := range overlay {
		_ = ob.AddPrefix(p)
	}
	ov, _ := ob.Build()
	want := routetable.Want{TUN: "thinkpol0", Overlay: overlay, Direct: local().Minus(ov), IPv6: true}
	d.ip(t, "addr", "add", "10.9.0.2/24", "dev", "eth0") // a private LAN: trusted on-link
	if err := e.Enforce(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	reapplies := e.Status().Reapplies
	d.ip(t, "addr", "add", "198.51.100.50/24", "dev", "eth0")
	d.ip(t, "-6", "route", "add", "2001:db8:ab::/64", "dev", "eth0", "proto", "kernel")
	d.ip(t, "route", "add", "100.64.0.0/24", "via", "192.0.2.1")
	d.ip(t, "addr", "add", "100.64.5.5/16", "dev", "eth0")
	d.ip(t, "-6", "route", "add", "fd12:3456:789a:1::/64", "dev", "eth0", "proto", "kernel")
	waitFor(t, func() bool { return e.Status().Reapplies > reapplies }, "a re-Apply after the network's changes")
	time.Sleep(500 * time.Millisecond) // the burst settles
	// A DHCP client on that public subnet adds its default route: the
	// gateway resolves on the physical interface, not into the tunnel,
	// and links follow it.
	d.ip(t, "route", "replace", "default", "via", "198.51.100.1", "dev", "eth0")
	if out := d.ip(t, "route", "show", "default"); !strings.Contains(out, "via 198.51.100.1 dev eth0") {
		t.Errorf("the default route on a public subnet: %s", out)
	}
	d.expect(t, map[string]string{
		"198.51.100.9":        "tunnel",  // on-link by a DHCP address
		"2001:db8:ab::9":      "tunnel",  // on-link by an advertisement
		"100.64.0.9":          "tunnel",  // a classless route into the overlay
		"100.64.7.7":          "tunnel",  // an address inside the overlay
		"fd12:3456:789a:1::9": "tunnel",  // an advertised prefix inside the overlay
		"10.9.0.7":            "on-link", // the private LAN still works
		"8.8.8.8":             "tunnel",
		"8.8.8.8 marked":      "via 198.51.100.1",
	})
	// Without IPv6 in the TUN, the overlay's IPv6 is unreachable, not
	// sent to the advertised on-link prefix inside it.
	want.IPv6 = false
	if err := e.Enforce(context.Background(), want); err != nil {
		t.Fatal(err)
	}
	d.expect(t, map[string]string{"fd12:3456:789a:1::9": "unreachable", "2001:db8:ab::9": "unreachable"})
}
