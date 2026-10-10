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
	"sync/atomic"
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

// fullConfig exercises everything the port has, dual-stack. Routes print
// with their table so a route outside the main one would show.
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
			{Dst: pfx("10.80.0.0/16"), Gateway: addr("100.64.0.1"), Metric: 7},
			{Dst: pfx("fd80::/48"), Interface: "ovl0", Metric: 7},
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
	"254 10.80.0.0/16 via 100.64.0.1 dev ovl0 metric 7",
	"254 fd80::/48 dev ovl0 metric 7",
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
	if err := c.Apply(context.Background(), netcfg.Config{Interfaces: []netcfg.Interface{{}}}); !errors.Is(err, netcfg.ErrClosed) {
		t.Errorf("Apply after Close: %v, want ErrClosed (before validation)", err)
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
		{Dst: pfx("fd91::/48"), Gateway: addr("fd12:3456:789a::1")},
	} {
		bad := cfg
		bad.Routes = append(slices.Clone(cfg.Routes), r)
		if err := c.Apply(context.Background(), bad); !errors.Is(err, netcfg.ErrConflict) {
			t.Errorf("Apply over a foreign %v: %v, want ErrConflict", r, err)
		}
		requireSame(t, "namespace after the conflict", applied, snapshot(t, n.h))
	}
	// The kernel holds one prefix length per address: wanting another one
	// would mean changing someone else's address.
	for _, p := range []netip.Prefix{pfx("100.64.0.7/24"), pfx("fd12:3456:789a::99/64")} {
		bad := cfg
		bad.Interfaces = []netcfg.Interface{{Name: "ovl0", Addrs: []netip.Prefix{p}}}
		if err := c.Apply(context.Background(), bad); !errors.Is(err, netcfg.ErrConflict) {
			t.Errorf("Apply with %v over a foreign address: %v, want ErrConflict", p, err)
		}
		requireSame(t, "namespace after the conflict", applied, snapshot(t, n.h))
	}

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "namespace after Close", before, snapshot(t, n.h))
}

// TestMain doubles as a process that applies a config and dies without
// Close, for the crash tests.
func TestMain(m *testing.M) {
	if path := os.Getenv("NETCFG_CRASH_NS"); path != "" {
		c, err := netcfg.NewInNamespace(path)
		if err == nil {
			err = c.Apply(context.Background(), crashConfigs[os.Getenv("NETCFG_CRASH_CONFIG")]())
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

var crashConfigs = map[string]func() netcfg.Config{
	"full": fullConfig,
	"many": func() netcfg.Config { return manyRoutes(manyRoutesCount) },
}

// crash applies a config from another process that exits without Close.
func (n *testNS) crash(t *testing.T, config string) {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "NETCFG_CRASH_NS="+n.path, "NETCFG_CRASH_CONFIG="+config)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("crashing process: %v: %s", err, out)
	}
}

const manyRoutesCount = 4000

// manyRoutes is a route-table-sized config: half IPv4 on-link /32s, half
// IPv6 /128s via a gateway.
func manyRoutes(count int) netcfg.Config {
	cfg := netcfg.Config{Interfaces: []netcfg.Interface{{
		Name:  "ovl0",
		Addrs: []netip.Prefix{pfx("100.64.0.7/10"), pfx("fd12:3456:789a::7/48")},
		Up:    true,
	}}}
	for i := range count / 2 {
		v4 := netip.AddrFrom4([4]byte{10, 200, byte(i >> 8), byte(i)})
		v6 := netip.AddrFrom16([16]byte{0xfd, 0x99, 14: byte(i >> 8), 15: byte(i)})
		cfg.Routes = append(cfg.Routes,
			netcfg.Route{Dst: netip.PrefixFrom(v4, 32), Interface: "ovl0"},
			netcfg.Route{Dst: netip.PrefixFrom(v6, 128), Gateway: addr("fd12:3456:789a::1")},
		)
	}
	return cfg
}

func TestTakesOverRoutesLeftByACrash(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	n.crash(t, "full")
	leftovers := snapshot(t, n.h)
	requireSame(t, "routes left by the crash", fullConfigRoutes, ownRoutes(t, n.h))

	// The new run moves an IPv6 route to another gateway. Its first try
	// fails: undoing it puts the leftovers back as they were.
	cfg := fullConfig()
	for i, r := range cfg.Routes {
		if r.Dst == pfx("fd79::/48") {
			cfg.Routes[i].Gateway = addr("fd12:3456:789a::2")
		}
	}
	c := n.configurator(t)
	bad := cfg
	bad.Routes = append(slices.Clone(cfg.Routes), badRoute)
	if err := c.Apply(context.Background(), bad); err == nil {
		t.Fatal("Apply with an unreachable gateway succeeded")
	}
	requireSame(t, "namespace after the failed takeover", leftovers, snapshot(t, n.h))

	if err := c.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	want := slices.Clone(fullConfigRoutes)
	want[slices.Index(want, "254 fd79::/48 via fd12:3456:789a::1 dev ovl0 metric 1024")] = "254 fd79::/48 via fd12:3456:789a::2 dev ovl0 metric 1024"
	requireSame(t, "routes after the takeover", want, ownRoutes(t, n.h))
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "routes after Close", nil, ownRoutes(t, n.h))
	// The addresses can't be told from someone else's: used, not owned,
	// so they stay (a TUN takes its addresses along when it goes).
	if got := snapshot(t, n.h); !slices.Contains(got, "addr ovl0 100.64.0.7/10") {
		t.Error("Close removed an address it didn't add")
	}
}

func TestReApplyAfterACrashIsLinear(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	start := time.Now()
	n.crash(t, "many")
	t.Logf("first Apply of %d routes (in a child process): %v", manyRoutesCount, time.Since(start))

	c := n.configurator(t)
	var err error
	var took time.Duration
	if ch := n.changes(t, func() {
		start := time.Now()
		err = c.Apply(context.Background(), manyRoutes(manyRoutesCount))
		took = time.Since(start)
	}); ch != 0 {
		t.Errorf("taking over %d identical routes made %d changes, want none", manyRoutesCount, ch)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("takeover Apply: %v", took)
	// One dump, then map lookups: well under a second. A dump per route
	// (quadratic) takes minutes at this size.
	if took > 3*time.Second {
		t.Errorf("takeover Apply of %d routes took %v", manyRoutesCount, took)
	}
	start = time.Now()
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	t.Logf("Close: %v", time.Since(start))
	requireSame(t, "routes after Close", nil, ownRoutes(t, n.h))
}

func TestReApplyRepairsOutsideChanges(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	before := snapshot(t, n.h)
	c := n.configurator(t)
	ctx := context.Background()
	if err := c.Apply(ctx, fullConfig()); err != nil {
		t.Fatal(err)
	}
	applied := snapshot(t, n.h)

	for _, outside := range [][]string{
		{"route", "del", "10.79.0.0/16"},
		{"-6", "route", "del", "fd79::/48"},
		{"addr", "del", "100.64.0.7/10", "dev", "ovl0"},
		{"addr", "del", "fd12:3456:789a::7/48", "dev", "ovl0"},
		{"link", "set", "ovl0", "mtu", "1500"},
	} {
		n.ip(t, outside...)
		if err := c.Apply(ctx, fullConfig()); err != nil {
			t.Fatalf("Apply after ip %v: %v", outside, err)
		}
		requireSame(t, fmt.Sprintf("namespace after ip %v and Apply", outside), applied, snapshot(t, n.h))
	}

	// The owner recreates the interface: everything that went with the old
	// one, gateway-only routes included, comes back on the new one.
	l, err := n.h.LinkByName("ovl0")
	if err != nil {
		t.Fatal(err)
	}
	if err := n.h.LinkDel(l); err != nil {
		t.Fatal(err)
	}
	n.dummy(t, "ovl0")
	if err := c.Apply(ctx, fullConfig()); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "routes on the recreated interface", fullConfigRoutes, ownRoutes(t, n.h))
	// A new interface has a new MAC address, so a new link-local address.
	requireSame(t, "namespace on the recreated interface", withoutLinkLocal(applied), withoutLinkLocal(snapshot(t, n.h)))

	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "namespace after Close", before, snapshot(t, n.h))
}

// cancelAfter is a context that ends after a number of Err checks, to stop
// Apply at a known point halfway through.
type cancelAfter struct {
	context.Context
	left *atomic.Int32
}

func (c cancelAfter) Err() error {
	if c.left.Add(-1) < 0 {
		return context.Canceled
	}
	return nil
}

func TestCancelledApplyLeavesNothing(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	before := snapshot(t, n.h)
	c := n.configurator(t)
	left := &atomic.Int32{}
	left.Store(5) // the interface, then four routes
	var err error
	if ch := n.changes(t, func() { err = c.Apply(cancelAfter{context.Background(), left}, fullConfig()) }); ch == 0 {
		t.Error("Apply stopped before changing anything; the test wants it stopped halfway")
	}
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply with a cancelled context: %v, want context.Canceled", err)
	}
	requireSame(t, "namespace after the cancelled Apply", before, snapshot(t, n.h))
}

func TestMTUChangedSinceIsKept(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	c := n.configurator(t)
	if err := c.Apply(context.Background(), fullConfig()); err != nil {
		t.Fatal(err)
	}
	n.ip(t, "link", "set", "ovl0", "mtu", "1400")
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	l, err := n.h.LinkByName("ovl0")
	if err != nil {
		t.Fatal(err)
	}
	if l.Attrs().MTU != 1400 || l.Attrs().Flags&net.FlagUp != 0 {
		t.Errorf("ovl0 after Close: mtu %d, flags %v; want someone else's 1400 kept, and down", l.Attrs().MTU, l.Attrs().Flags)
	}
}

func TestSameRouteTwiceIsRejectedBeforeAnyChange(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	before := snapshot(t, n.h)
	c := n.configurator(t)
	cfg := fullConfig()
	// Metric 0 is 1024 for IPv6 in the kernel: the same route as fd78::/48.
	cfg.Routes = append(cfg.Routes, netcfg.Route{Dst: pfx("fd78::/48"), Gateway: addr("fd12:3456:789a::1"), Metric: 1024})
	var err error
	if ch := n.changes(t, func() { err = c.Apply(context.Background(), cfg) }); ch != 0 {
		t.Errorf("rejected Apply made %d changes", ch)
	}
	if err == nil {
		t.Fatal("Apply with the same route twice succeeded")
	}
	requireSame(t, "namespace", before, snapshot(t, n.h))
}

func TestTwoConfiguratorsInOneNamespace(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	before := snapshot(t, n.h)
	ctx := context.Background()
	first := n.configurator(t)
	if err := first.Apply(ctx, netcfg.Config{
		Interfaces: []netcfg.Interface{{Name: "ovl0", Addrs: []netip.Prefix{pfx("100.64.0.7/10")}, Up: true}},
		Routes:     []netcfg.Route{{Dst: pfx("10.78.0.0/16"), Interface: "ovl0"}},
	}); err != nil {
		t.Fatal(err)
	}
	// The first is alive, so its routes are not leftovers to take over.
	second := n.configurator(t)
	if err := second.Apply(ctx, netcfg.Config{Routes: []netcfg.Route{{Dst: pfx("10.78.0.0/16"), Interface: "ovl0"}}}); !errors.Is(err, netcfg.ErrConflict) {
		t.Errorf("second configurator claiming the first's route: %v, want ErrConflict", err)
	}
	requireSame(t, "routes", []string{"254 10.78.0.0/16 dev ovl0 metric 0"}, ownRoutes(t, n.h))
	if err := second.Apply(ctx, netcfg.Config{Routes: []netcfg.Route{{Dst: pfx("10.85.0.0/16"), Interface: "ovl0"}}}); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "routes", []string{"254 10.78.0.0/16 dev ovl0 metric 0", "254 10.85.0.0/16 dev ovl0 metric 0"}, ownRoutes(t, n.h))
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "routes after the second closed", []string{"254 10.78.0.0/16 dev ovl0 metric 0"}, ownRoutes(t, n.h))
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "namespace after both closed", before, snapshot(t, n.h))
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
	// A better default route on a link without carrier is not usable.
	n.ip(t, "link", "add", "veth9", "type", "veth", "peer", "name", "veth9p")
	n.ip(t, "link", "set", "veth9", "up")
	n.ip(t, "addr", "add", "198.51.100.10/24", "dev", "veth9")
	n.ip(t, "addr", "add", "2001:db8:1::10/64", "dev", "veth9", "nodad")
	n.ip(t, "link", "set", "veth9p", "up")
	n.ip(t, "route", "add", "default", "via", "198.51.100.1", "metric", "10")
	n.ip(t, "-6", "route", "add", "default", "via", "2001:db8:1::1", "dev", "veth9", "metric", "10")
	n.ip(t, "link", "set", "veth9p", "down")

	c := n.configurator(t)
	ctx := context.Background()
	if _, err := c.DefaultRoute(ctx, netcfg.IPv6); !errors.Is(err, netcfg.ErrNoDefaultRoute) {
		t.Errorf("IPv6 default route without carrier: %v, want ErrNoDefaultRoute", err)
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
