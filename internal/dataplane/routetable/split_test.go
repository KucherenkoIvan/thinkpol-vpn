package routetable_test

import (
	"net/netip"
	"runtime"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// home is a Mac on a home network: Wi-Fi with a private subnet and both
// families' default routes.
func home(onLink ...string) netcfg.Survey {
	s := netcfg.Survey{
		Links: []netcfg.Link{{Name: "en0", Up: true}, {Name: "lo0", Up: true}, {Name: "utun7", Up: true}},
		Defaults: []netcfg.Route{
			{Dst: pfx("0.0.0.0/0"), Gateway: netip.MustParseAddr("192.168.1.1"), Interface: "en0"},
			{Dst: pfx("::/0"), Gateway: netip.MustParseAddr("fe80::1"), Interface: "en0"},
		},
	}
	for _, p := range append([]string{"192.168.1.0/24", "169.254.0.0/16", "224.0.0.0/4", "255.255.255.255/32", "192.168.1.20/32"}, onLink...) {
		s.OnLink = append(s.OnLink, pfx(p))
	}
	return s
}

func localPlus(t testing.TB, extra ...string) *lists.Set {
	var b lists.Builder
	b.AddSet(lists.Local())
	for _, p := range extra {
		if err := b.AddPrefix(pfx(p)); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := b.Build()
	return s
}

func routes(cfg netcfg.Config) map[string]bool {
	out := map[string]bool{}
	for _, r := range cfg.Routes {
		out[r.String()] = true
	}
	return out
}

// darwinValid checks what the macOS adapter takes: valid, no metrics,
// tables, throws or default routes, no destination twice.
func darwinValid(t *testing.T, cfg netcfg.Config) {
	t.Helper()
	if err := cfg.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Rules) > 0 {
		t.Errorf("rules %v", cfg.Rules)
	}
	seen := map[netip.Prefix]bool{}
	for _, r := range cfg.Routes {
		if r.Metric != 0 || r.Table != 0 || r.Type == netcfg.RouteThrow || r.Dst.Bits() == 0 || seen[r.Dst] {
			t.Errorf("route %v", r)
		}
		seen[r.Dst] = true
	}
}

func TestSplitRoutesOnAHomeNetwork(t *testing.T) {
	w := routetable.Want{TUN: "utun7", Overlay: overlay, Direct: localPlus(t, "203.0.113.0/24"),
		Bypass: []netip.Addr{netip.MustParseAddr("198.51.100.7"), netip.MustParseAddr("2001:db8::7")}, IPv6: true}
	cfg := routetable.SplitRoutes(w, home())
	darwinValid(t, cfg)
	got := routes(cfg)
	for _, want := range []string{
		"0.0.0.0/1 dev utun7", "128.0.0.0/1 dev utun7",
		"::/2 dev utun7", "4000::/2 dev utun7", "8000::/2 dev utun7", "c000::/2 dev utun7",
		"unreachable ::/1", "unreachable 8000::/1",
		"10.0.0.0/8 via 192.168.1.1 dev en0", "192.168.0.0/16 via 192.168.1.1 dev en0",
		"203.0.113.0/24 via 192.168.1.1 dev en0",
		"198.51.100.7/32 via 192.168.1.1 dev en0", "2001:db8::7/128 via fe80::1 dev en0",
		"fc00::/8 via fe80::1 dev en0",
		// Behind the overlay configurator's halves, for a crash.
		"unreachable 100.64.0.0/10", "unreachable fd12:3456:789a::/48",
	} {
		if !got[want] {
			t.Errorf("no %q", want)
		}
	}
	for r := range got {
		if strings.HasPrefix(r, "unreachable ") {
			continue
		}
		dst := netip.MustParsePrefix(strings.Fields(r)[0])
		// The overlay is never direct, and what the OS routes on its own
		// interfaces (link-local, multicast, the LAN) gets no route.
		for _, never := range []string{"100.64.0.0/10", "fd12:3456:789a::/48", "169.254.0.0/16", "224.0.0.0/4", "fe80::/10", "ff00::/8", "192.168.1.0/24"} {
			if n := netip.MustParsePrefix(never); n.Overlaps(dst) && dst.Bits() >= n.Bits() {
				t.Errorf("%s: a route inside %s", r, never)
			}
		}
	}
	if n := routetable.Ahead(w, home()); runtime.GOOS == "darwin" && n != 0 {
		t.Errorf("%d ahead", n)
	}
}

// What the TUN can't take is rejected, never sent around the tunnel.
func TestSplitRoutesWithoutIPv6OrTheTUN(t *testing.T) {
	w := routetable.Want{TUN: "utun7", Overlay: overlay, Direct: localPlus(t), IPv6: false}
	got := routes(routetable.SplitRoutes(w, home()))
	for _, r := range []string{"0.0.0.0/1 dev utun7", "128.0.0.0/1 dev utun7", "unreachable ::/1", "unreachable 8000::/1"} {
		if !got[r] {
			t.Errorf("IPv6 off: no %q", r)
		}
	}
	if got["::/2 dev utun7"] {
		t.Error("IPv6 off: IPv6 into the TUN")
	}
	down := home()
	down.Links[2].Up = false
	w.IPv6 = true
	got = routes(routetable.SplitRoutes(w, down))
	for _, r := range []string{"unreachable 0.0.0.0/1", "unreachable 128.0.0.0/1", "unreachable ::/1", "unreachable 8000::/1"} {
		if !got[r] {
			t.Errorf("TUN down: no %q", r)
		}
	}
	for r := range got {
		if strings.Contains(r, "utun7") {
			t.Errorf("TUN down: %s", r)
		}
	}
}

// All of IPv4 direct: the halves go via the gateway (the OS's default
// route can't be replaced), but for the overlay, which stays in the TUN.
func TestSplitRoutesWithEverythingDirect(t *testing.T) {
	w := routetable.Want{TUN: "utun7", Overlay: overlay, Direct: set(t, "0.0.0.0/0")}
	cfg := routetable.SplitRoutes(w, home())
	darwinValid(t, cfg)
	got := routes(cfg)
	for _, r := range []string{"128.0.0.0/1 via 192.168.1.1 dev en0", "0.0.0.0/2 via 192.168.1.1 dev en0",
		"100.0.0.0/10 via 192.168.1.1 dev en0", "100.128.0.0/9 via 192.168.1.1 dev en0", "0.0.0.0/1 dev utun7", "unreachable ::/1"} {
		if !got[r] {
			t.Errorf("no %q in %v", r, got)
		}
	}
	if got["128.0.0.0/1 dev utun7"] {
		t.Error("a direct half into the TUN")
	}
	// No default route for a family: its direct prefixes have nowhere to go
	// but the tunnel.
	s := home()
	s.Defaults = s.Defaults[1:]
	if got := routes(routetable.SplitRoutes(w, s)); !got["0.0.0.0/1 dev utun7"] || got["0.0.0.0/1 via 192.168.1.1 dev en0"] {
		t.Errorf("no IPv4 default route: %v", got)
	}
}

// A hostile network's routes (TunnelVision, LocalNet): a public "on-link"
// subnet, DHCP classless routes over foreign and overlay destinations, a
// router advertisement's prefix. Each is outranked by more specific
// routes into the TUN, but for the gateway; a host route can't be, and
// counts as ahead.
func TestSplitRoutesShadowAHostileNetwork(t *testing.T) {
	s := home("198.51.100.0/24", "2001:db8:ab::/64", "100.64.7.0/24")
	s.Defaults[0].Gateway = netip.MustParseAddr("198.51.100.1")
	s.Routes = []netcfg.Route{
		{Dst: pfx("8.8.8.0/24"), Gateway: netip.MustParseAddr("198.51.100.1"), Interface: "en0"},
		{Dst: pfx("100.64.0.0/24"), Gateway: netip.MustParseAddr("198.51.100.1"), Interface: "en0"},
		{Dst: pfx("100.0.0.0/9"), Gateway: netip.MustParseAddr("198.51.100.1"), Interface: "en0"},
		{Dst: pfx("9.9.9.9/32"), Gateway: netip.MustParseAddr("198.51.100.1"), Interface: "en0"},
		{Dst: pfx("10.8.0.0/16"), Interface: "utun100"}, // another VPN's, inside direct
		{Dst: pfx("100.64.0.0/16"), Interface: "utun7"}, // on our TUN: ours already
		{Dst: pfx("2001:db8:ab:1::/64"), Gateway: netip.MustParseAddr("fe80::1"), Interface: "en0"},
	}
	w := routetable.Want{TUN: "utun7", Overlay: overlay, Direct: localPlus(t), IPv6: true}
	cfg := routetable.SplitRoutes(w, s)
	darwinValid(t, cfg)
	got := routes(cfg)
	for _, r := range []string{
		"8.8.8.0/25 dev utun7", "8.8.8.128/25 dev utun7",
		"100.64.0.0/25 dev utun7", "100.64.0.128/25 dev utun7",
		"100.64.7.0/25 dev utun7", "100.64.7.128/25 dev utun7",
		// 100.0.0.0/9 but the overlay, whose own halves outrank it.
		"100.0.0.0/10 dev utun7",
		// The public subnet, its gateway included: a hostile network's
		// gateway gets nothing in the clear.
		"198.51.100.0/25 dev utun7", "198.51.100.128/25 dev utun7",
		"unreachable 100.64.0.0/10",
		"2001:db8:ab::/65 dev utun7", "2001:db8:ab:0:8000::/65 dev utun7",
		"2001:db8:ab:1::/65 dev utun7",
	} {
		if !got[r] {
			t.Errorf("no %q", r)
		}
	}
	for r := range got {
		if strings.HasPrefix(r, "10.8.") || strings.HasPrefix(r, "192.168.1.") || strings.HasPrefix(r, "100.64.0.0/11") || strings.HasPrefix(r, "100.96.0.0/11") {
			t.Errorf("%s: direct destinations, trusted subnets and the overlay configurator's routes stay as they are", r)
		}
	}
	if runtime.GOOS == "darwin" {
		if n := routetable.Ahead(w, s); n != 1 {
			t.Errorf("%d ahead, want 1 (9.9.9.9/32)", n)
		}
	}
	// Without IPv6 in the TUN, the advertised prefix is rejected instead.
	w.IPv6 = false
	if got := routes(routetable.SplitRoutes(w, s)); !got["unreachable 2001:db8:ab::/65"] {
		t.Error("IPv6 off: the advertised prefix isn't rejected")
	}
}

// Another VPN's own split routes (and IPv6 halves), someone's reject
// route on an endpoint: the layout never takes an identity they hold, it
// goes more specific, so applying it can't conflict.
func TestSplitRoutesNeverTakeAnIdentityAnotherRouteHolds(t *testing.T) {
	s := home()
	s.Routes = []netcfg.Route{
		{Dst: pfx("0.0.0.0/1"), Interface: "utun100"},
		{Dst: pfx("128.0.0.0/1"), Interface: "utun100"},
		{Dst: pfx("::/1"), Interface: "utun100"},
	}
	s.Held = []netip.Prefix{pfx("0.0.0.0/1"), pfx("128.0.0.0/1"), pfx("::/1"), pfx("198.51.100.7/32"), pfx("127.0.0.0/8")}
	held := map[netip.Prefix]bool{}
	for _, p := range s.Held {
		held[p] = true
	}
	for _, ipv6 := range []bool{true, false} {
		w := routetable.Want{TUN: "utun7", Overlay: overlay, Direct: localPlus(t),
			Bypass: []netip.Addr{netip.MustParseAddr("198.51.100.7")}, IPv6: ipv6}
		cfg := routetable.SplitRoutes(w, s)
		darwinValid(t, cfg)
		for _, r := range cfg.Routes {
			if held[r.Dst] {
				t.Errorf("IPv6 %v: %v takes another route's identity", ipv6, r)
			}
		}
		got := routes(cfg)
		for _, r := range []string{"0.0.0.0/2 dev utun7", "64.0.0.0/2 dev utun7", "128.0.0.0/2 dev utun7", "192.0.0.0/2 dev utun7", "unreachable 8000::/1"} {
			if !got[r] {
				t.Errorf("IPv6 %v: no %q", ipv6, r)
			}
		}
		if ipv6 && !got["::/2 dev utun7"] {
			t.Error("IPv6 into the TUN beneath the other VPN's ::/1")
		}
		if !ipv6 && (!got["unreachable ::/2"] || !got["unreachable 4000::/2"]) {
			t.Errorf("IPv6 off: the other VPN's ::/1 isn't rejected beneath: %v", got)
		}
	}
}

// A hostile network's DHCP puts the Mac and its gateway inside the
// overlay's range (100.64.0.77/24 via 100.64.0.1), and a classless host
// route on a peer's overlay address: the gateway gets no on-link route in
// the clear, and the host route, which nothing outranks, is an overlay
// hijack the status reports.
func TestAGatewayInsideTheOverlayIsNotExempt(t *testing.T) {
	s := home("100.64.0.0/24")
	s.Defaults[0].Gateway = netip.MustParseAddr("100.64.0.1")
	s.Routes = []netcfg.Route{{Dst: pfx("100.64.0.9/32"), Gateway: netip.MustParseAddr("100.64.0.1"), Interface: "en0"}}
	w := routetable.Want{TUN: "utun7", Overlay: overlay, Direct: localPlus(t), IPv6: true}
	cfg := routetable.SplitRoutes(w, s)
	darwinValid(t, cfg)
	got := routes(cfg)
	for _, r := range []string{"100.64.0.0/25 dev utun7", "100.64.0.128/25 dev utun7", "unreachable 100.64.0.0/10"} {
		if !got[r] {
			t.Errorf("no %q", r)
		}
	}
	if runtime.GOOS == "darwin" {
		if n := routetable.OverlayAhead(w, s); n != 1 {
			t.Errorf("%d overlay routes ahead, want 1", n)
		}
		if n := routetable.Ahead(w, s); n != 0 {
			t.Errorf("%d other routes ahead", n)
		}
	}
}
