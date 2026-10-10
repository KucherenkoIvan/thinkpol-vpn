//go:build linux && !android

package netcfg_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

// testNS is a fresh network namespace, deleted when the test ends, with a
// netlink handle into it for setting up and checking state independently of
// the configurator.
type testNS struct {
	path string
	ns   netns.NsHandle
	h    *netlink.Handle
}

func newTestNS(t *testing.T) *testNS {
	t.Helper()
	if os.Getenv("THINKPOL_LAB") == "" {
		t.Skip("needs the lab")
	}
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	name := "netcfg-" + hex.EncodeToString(b)
	if out, err := exec.Command("ip", "netns", "add", name).CombinedOutput(); err != nil {
		t.Fatalf("ip netns add: %v: %s", err, out)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("ip", "netns", "del", name).CombinedOutput(); err != nil {
			t.Errorf("ip netns del: %v: %s", err, out)
		}
	})
	path := "/run/netns/" + name
	ns, err := netns.GetFromPath(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ns.Close() })
	h, err := netlink.NewHandleAt(ns)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.Close)
	return &testNS{path: path, ns: ns, h: h}
}

func (n *testNS) dummy(t *testing.T, name string) netlink.Link {
	t.Helper()
	if err := n.h.LinkAdd(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: name, MTU: 1500}}); err != nil {
		t.Fatalf("add %s: %v", name, err)
	}
	l, err := n.h.LinkByName(name)
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func (n *testNS) configurator(t *testing.T) netcfg.Configurator {
	t.Helper()
	c, err := netcfg.NewInNamespace(n.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// ip runs iproute2 in the namespace, for state set up by "someone else".
func (n *testNS) ip(t *testing.T, args ...string) {
	t.Helper()
	args = append([]string{"-n", strings.TrimPrefix(n.path, "/run/netns/")}, args...)
	if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
}

// snapshot is everything netcfg could touch in a namespace: links, every
// address and every route in every table, as sorted lines.
func snapshot(t *testing.T, h *netlink.Handle) []string {
	t.Helper()
	var out []string
	links, err := h.LinkList()
	if err != nil {
		t.Fatal(err)
	}
	names := map[int]string{}
	for _, l := range links {
		a := l.Attrs()
		names[a.Index] = a.Name
		out = append(out, fmt.Sprintf("link %s mtu %d up=%v", a.Name, a.MTU, a.Flags&net.FlagUp != 0))
		addrs, err := h.AddrList(l, netlink.FAMILY_ALL)
		if err != nil {
			t.Fatal(err)
		}
		for _, ad := range addrs {
			out = append(out, fmt.Sprintf("addr %s %s", a.Name, ad.IPNet))
		}
	}
	routes, err := h.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range routes {
		out = append(out, "route "+routeLine(r, names))
	}
	slices.Sort(out)
	return out
}

func routeLine(r netlink.Route, names map[int]string) string {
	s := fmt.Sprintf("table %d %v", r.Table, r.Dst)
	if r.Gw != nil {
		s += " via " + r.Gw.String()
	}
	return s + fmt.Sprintf(" dev %s metric %d proto %d type %d", names[r.LinkIndex], r.Priority, r.Protocol, r.Type)
}

// ownRoutes lists the routes carrying netcfg's protocol, in a compact form.
func ownRoutes(t *testing.T, h *netlink.Handle) []string {
	t.Helper()
	routes, err := h.RouteListFiltered(netlink.FAMILY_ALL, &netlink.Route{Table: unix.RT_TABLE_UNSPEC, Protocol: netcfg.RouteProtocol}, netlink.RT_FILTER_TABLE|netlink.RT_FILTER_PROTOCOL)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range routes {
		l, err := h.LinkByIndex(r.LinkIndex)
		if err != nil {
			t.Fatal(err)
		}
		s := fmt.Sprintf("%d %v", r.Table, r.Dst)
		if ones, _ := r.Dst.Mask.Size(); r.Dst == nil || ones == 0 {
			s = fmt.Sprintf("%d default", r.Table)
		}
		if r.Gw != nil {
			s += " via " + r.Gw.String()
		}
		out = append(out, s+fmt.Sprintf(" dev %s metric %d", l.Attrs().Name, r.Priority))
	}
	slices.Sort(out)
	return out
}

func withoutLinkLocal(lines []string) []string {
	return slices.DeleteFunc(slices.Clone(lines), func(s string) bool { return strings.Contains(s, " fe80:") })
}

func diff(want, got []string) string {
	var b strings.Builder
	for _, s := range want {
		if !slices.Contains(got, s) {
			b.WriteString("\n  missing: " + s)
		}
	}
	for _, s := range got {
		if !slices.Contains(want, s) {
			b.WriteString("\n  extra:   " + s)
		}
	}
	return b.String()
}

func requireSame(t *testing.T, what string, want, got []string) {
	t.Helper()
	if d := diff(want, got); d != "" {
		t.Fatalf("%s:%s", what, d)
	}
}

// changes counts address and route events (ours, or for non-link-local
// addresses) in the namespace while f runs, so a no-op can be told from a
// remove-and-re-add.
func (n *testNS) changes(t *testing.T, f func()) int {
	t.Helper()
	done := make(chan struct{})
	routes := make(chan netlink.RouteUpdate, 1024)
	addrs := make(chan netlink.AddrUpdate, 1024)
	ns := n.ns
	if err := netlink.RouteSubscribeWithOptions(routes, done, netlink.RouteSubscribeOptions{Namespace: &ns}); err != nil {
		t.Fatal(err)
	}
	if err := netlink.AddrSubscribeWithOptions(addrs, done, netlink.AddrSubscribeOptions{Namespace: &ns}); err != nil {
		close(done)
		t.Fatal(err)
	}
	f()
	count := 0
	timeout := time.After(300 * time.Millisecond)
	for {
		select {
		case u := <-routes:
			if u.Protocol == netcfg.RouteProtocol {
				count++
			}
		case u := <-addrs:
			if !u.LinkAddress.IP.IsLinkLocalUnicast() {
				count++
			}
		case <-timeout:
			close(done)
			return count
		}
	}
}

// fullConfig exercises everything the port has, dual-stack.
func fullConfig() netcfg.Config {
	return netcfg.Config{
		Interfaces: []netcfg.Interface{{
			Name:  "ovl0",
			Addrs: []netip.Prefix{pfx("100.64.0.7/10"), pfx("fd12:3456:789a::7/48")},
			MTU:   1380,
			Up:    true,
		}},
		Routes: []netcfg.Route{
			{Dst: pfx("10.78.0.0/16"), Interface: "ovl0"},
			{Dst: pfx("fd78::/48"), Interface: "ovl0"},
			{Dst: pfx("10.79.0.0/16"), Gateway: addr("100.64.0.1")},
			{Dst: pfx("fd79::/48"), Gateway: addr("fd12:3456:789a::1"), Interface: "ovl0"},
			{Dst: pfx("0.0.0.0/0"), Gateway: addr("100.64.0.1"), Interface: "ovl0"},
			{Dst: pfx("::/0"), Gateway: addr("fd12:3456:789a::1")},
			{Dst: pfx("10.80.0.0/16"), Gateway: addr("100.64.0.1"), Table: 100},
			{Dst: pfx("fd80::/48"), Interface: "ovl0", Table: 100, Metric: 7},
		},
	}
}

var fullConfigRoutes = []string{
	"254 10.78.0.0/16 dev ovl0 metric 0",
	"254 fd78::/48 dev ovl0 metric 1024",
	"254 10.79.0.0/16 via 100.64.0.1 dev ovl0 metric 0",
	"254 fd79::/48 via fd12:3456:789a::1 dev ovl0 metric 1024",
	"254 default via 100.64.0.1 dev ovl0 metric 0",
	"254 default via fd12:3456:789a::1 dev ovl0 metric 1024",
	"100 10.80.0.0/16 via 100.64.0.1 dev ovl0 metric 0",
	"100 fd80::/48 dev ovl0 metric 7",
}

func TestApplyThenCloseRestoresEverything(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	before := snapshot(t, n.h)
	root, err := netlink.NewHandle()
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	rootBefore := snapshot(t, root)

	c := n.configurator(t)
	if err := c.Apply(context.Background(), fullConfig()); err != nil {
		t.Fatal(err)
	}

	l, err := n.h.LinkByName("ovl0")
	if err != nil {
		t.Fatal(err)
	}
	if l.Attrs().MTU != 1380 || l.Attrs().Flags&net.FlagUp == 0 {
		t.Errorf("ovl0: mtu %d, flags %v; want 1380 and up", l.Attrs().MTU, l.Attrs().Flags)
	}
	got := snapshot(t, n.h)
	for _, a := range []string{"addr ovl0 100.64.0.7/10", "addr ovl0 fd12:3456:789a::7/48"} {
		if !slices.Contains(got, a) {
			t.Errorf("missing %s in\n%s", a, strings.Join(got, "\n"))
		}
	}
	requireSame(t, "routes after Apply", fullConfigRoutes, ownRoutes(t, n.h))

	if ch := n.changes(t, func() {
		if err := c.Apply(context.Background(), fullConfig()); err != nil {
			t.Error(err)
		}
	}); ch != 0 {
		t.Errorf("re-applying the same config made %d changes, want none", ch)
	}
	requireSame(t, "namespace after re-Apply", got, snapshot(t, n.h))

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "namespace after Close", before, snapshot(t, n.h))
	// The node's own link-local addresses come and go with DAD on their own.
	requireSame(t, "the test's own namespace", withoutLinkLocal(rootBefore), withoutLinkLocal(snapshot(t, root)))
	if err := c.Close(); err != nil {
		t.Errorf("second Close: %v", err)
	}
	if err := c.Apply(context.Background(), fullConfig()); !errors.Is(err, netcfg.ErrClosed) {
		t.Errorf("Apply after Close: %v, want ErrClosed", err)
	}
}

// badRoute fails in the kernel: no address of ovl0 reaches the gateway.
var badRoute = netcfg.Route{Dst: pfx("10.99.0.0/16"), Gateway: addr("192.0.2.1"), Interface: "ovl0"}

func TestFailedFirstApplyLeavesNothing(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	before := snapshot(t, n.h)

	c := n.configurator(t)
	cfg := fullConfig()
	cfg.Routes = append(cfg.Routes, badRoute)
	var err error
	if ch := n.changes(t, func() { err = c.Apply(context.Background(), cfg) }); ch == 0 {
		t.Error("Apply failed before changing anything; the test wants a failure halfway through")
	}
	if err == nil {
		t.Fatal("Apply with an unreachable gateway succeeded")
	}
	t.Logf("Apply: %v", err)
	requireSame(t, "namespace after the failed Apply", before, snapshot(t, n.h))

	// A missing interface fails too, after everything else was applied.
	cfg = fullConfig()
	cfg.Routes = append(cfg.Routes, netcfg.Route{Dst: pfx("10.98.0.0/16"), Interface: "nope0"})
	if err := c.Apply(context.Background(), cfg); err == nil {
		t.Fatal("Apply with a missing interface succeeded")
	}
	requireSame(t, "namespace after the second failed Apply", before, snapshot(t, n.h))

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "namespace after Close", before, snapshot(t, n.h))
}

func TestFailedUpdateKeepsThePreviousConfig(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	before := snapshot(t, n.h)
	c := n.configurator(t)
	if err := c.Apply(context.Background(), fullConfig()); err != nil {
		t.Fatal(err)
	}
	applied := snapshot(t, n.h)

	update := updatedConfig()
	update.Routes = append(update.Routes, badRoute)
	if err := c.Apply(context.Background(), update); err == nil {
		t.Fatal("Apply with an unreachable gateway succeeded")
	}
	requireSame(t, "namespace after the failed update", applied, snapshot(t, n.h))

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "namespace after Close", before, snapshot(t, n.h))
}

// updatedConfig differs from fullConfig in every way Apply has to converge:
// MTU, an address dropped and one added, routes dropped, added, and one with
// a new gateway under the same identity.
func updatedConfig() netcfg.Config {
	return netcfg.Config{
		Interfaces: []netcfg.Interface{{
			Name:  "ovl0",
			Addrs: []netip.Prefix{pfx("100.64.0.7/10"), pfx("fd12:3456:789a::8/48")},
			MTU:   1420,
			Up:    true,
		}},
		Routes: []netcfg.Route{
			{Dst: pfx("10.78.0.0/16"), Interface: "ovl0"},
			{Dst: pfx("10.79.0.0/16"), Gateway: addr("100.64.0.2")},
			{Dst: pfx("::/0"), Gateway: addr("fd12:3456:789a::1")},
			{Dst: pfx("10.81.0.0/16"), Interface: "ovl0", Metric: 5},
		},
	}
}

func TestApplyConverges(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	before := snapshot(t, n.h)
	c := n.configurator(t)
	if err := c.Apply(context.Background(), fullConfig()); err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(context.Background(), updatedConfig()); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "routes after the update", []string{
		"254 10.78.0.0/16 dev ovl0 metric 0",
		"254 10.79.0.0/16 via 100.64.0.2 dev ovl0 metric 0",
		"254 default via fd12:3456:789a::1 dev ovl0 metric 1024",
		"254 10.81.0.0/16 dev ovl0 metric 5",
	}, ownRoutes(t, n.h))
	got := snapshot(t, n.h)
	for _, want := range []string{"addr ovl0 100.64.0.7/10", "addr ovl0 fd12:3456:789a::8/48", "link ovl0 mtu 1420 up=true"} {
		if !slices.Contains(got, want) {
			t.Errorf("missing %s", want)
		}
	}
	if slices.Contains(got, "addr ovl0 fd12:3456:789a::7/48") {
		t.Error("the dropped address is still there")
	}

	// Leaving the interface out of the config gives it back as it was.
	if err := c.Apply(context.Background(), netcfg.Config{}); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "namespace after an empty config", before, snapshot(t, n.h))
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestForeignStateIsNeverTouched(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	// Someone else's: the link up, an address we also want, an address we
	// don't, a route next to ours, and a route we will collide with.
	n.ip(t, "link", "set", "ovl0", "up")
	n.ip(t, "addr", "add", "100.64.0.7/10", "dev", "ovl0")
	n.ip(t, "addr", "add", "fd12:3456:789a::99/48", "dev", "ovl0", "nodad")
	n.ip(t, "route", "add", "10.90.0.0/16", "dev", "ovl0", "metric", "10", "proto", "static")
	n.ip(t, "route", "add", "10.91.0.0/16", "dev", "ovl0", "proto", "static")
	n.ip(t, "-6", "route", "add", "fd91::/48", "dev", "ovl0", "proto", "static")
	before := snapshot(t, n.h)

	c := n.configurator(t)
	cfg := netcfg.Config{
		Interfaces: []netcfg.Interface{{Name: "ovl0", Addrs: []netip.Prefix{pfx("100.64.0.7/10"), pfx("fd12:3456:789a::7/48")}, Up: true}},
		Routes:     []netcfg.Route{{Dst: pfx("10.90.0.0/16"), Interface: "ovl0", Metric: 20}},
	}
	if err := c.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	applied := snapshot(t, n.h)

	for _, r := range []netcfg.Route{
		{Dst: pfx("10.91.0.0/16"), Gateway: addr("100.64.0.1")},
		{Dst: pfx("fd91::/48"), Interface: "ovl0"},
	} {
		bad := cfg
		bad.Routes = append(slices.Clone(cfg.Routes), r)
		if err := c.Apply(context.Background(), bad); !errors.Is(err, netcfg.ErrConflict) {
			t.Errorf("Apply over a foreign %v: %v, want ErrConflict", r, err)
		}
		requireSame(t, "namespace after the conflict", applied, snapshot(t, n.h))
	}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "namespace after Close", before, snapshot(t, n.h))
}

func TestTakesOverRoutesLeftByACrash(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	crashed := n.configurator(t)
	if err := crashed.Apply(context.Background(), fullConfig()); err != nil {
		t.Fatal(err)
	}
	// The process died: its configurator never closes. A new one applies
	// the same config over the leftovers: the routes carry our protocol, so
	// it takes them over and removes them on Close. The addresses can't be
	// told from someone else's, so they are used but left alone (a TUN takes
	// them along when it goes; routes via a physical interface stay, which
	// is why routes are tagged).
	c := n.configurator(t)
	if err := c.Apply(context.Background(), fullConfig()); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "routes", fullConfigRoutes, ownRoutes(t, n.h))
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "routes after Close", nil, ownRoutes(t, n.h))
	if got := snapshot(t, n.h); !slices.Contains(got, "addr ovl0 100.64.0.7/10") {
		t.Error("Close removed an address it didn't add")
	}
}

func TestCloseAfterTheInterfaceIsGone(t *testing.T) {
	n := newTestNS(t)
	l := n.dummy(t, "ovl0")
	c := n.configurator(t)
	if err := c.Apply(context.Background(), fullConfig()); err != nil {
		t.Fatal(err)
	}
	if err := n.h.LinkDel(l); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close after the interface was deleted: %v", err)
	}
}

func TestDefaultRoute(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "eth9")
	n.dummy(t, "ovl0")
	n.ip(t, "link", "set", "eth9", "up")
	n.ip(t, "addr", "add", "192.0.2.10/24", "dev", "eth9")
	n.ip(t, "route", "add", "default", "via", "192.0.2.1", "metric", "100")
	n.ip(t, "route", "add", "default", "via", "192.0.2.2", "metric", "50")

	c := n.configurator(t)
	ctx := context.Background()
	if _, err := c.DefaultRoute(ctx, netcfg.IPv6); !errors.Is(err, netcfg.ErrNoDefaultRoute) {
		t.Errorf("IPv6 default route: %v, want ErrNoDefaultRoute", err)
	}
	// Our own default route, even a better one, is not the physical gateway.
	cfg := netcfg.Config{
		Interfaces: []netcfg.Interface{{Name: "ovl0", Addrs: []netip.Prefix{pfx("100.64.0.7/10"), pfx("fd12:3456:789a::7/48")}, Up: true}},
		Routes: []netcfg.Route{
			{Dst: pfx("0.0.0.0/0"), Interface: "ovl0", Metric: 1},
			{Dst: pfx("::/0"), Interface: "ovl0", Metric: 1},
		},
	}
	if err := c.Apply(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := c.DefaultRoute(ctx, netcfg.IPv4)
	if err != nil {
		t.Fatal(err)
	}
	want := netcfg.Route{Dst: pfx("0.0.0.0/0"), Gateway: addr("192.0.2.2"), Interface: "eth9", Metric: 50}
	if got != want {
		t.Errorf("IPv4 default route: %v, want %v", got, want)
	}
	if _, err := c.DefaultRoute(ctx, netcfg.IPv6); !errors.Is(err, netcfg.ErrNoDefaultRoute) {
		t.Errorf("IPv6 default route with only ours: %v, want ErrNoDefaultRoute", err)
	}
	n.ip(t, "addr", "add", "2001:db8::10/64", "dev", "eth9", "nodad")
	n.ip(t, "-6", "route", "add", "default", "via", "2001:db8::1", "dev", "eth9")
	got, err = c.DefaultRoute(ctx, netcfg.IPv6)
	if err != nil {
		t.Fatal(err)
	}
	want = netcfg.Route{Dst: pfx("::/0"), Gateway: addr("2001:db8::1"), Interface: "eth9", Metric: 1024}
	if got != want {
		t.Errorf("IPv6 default route: %v, want %v", got, want)
	}
}
