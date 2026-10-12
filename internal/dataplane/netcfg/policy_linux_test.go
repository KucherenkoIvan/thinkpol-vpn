//go:build linux && !android

package netcfg_test

import (
	"context"
	"errors"
	"net/netip"
	"os/exec"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vishvananda/netlink"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

const policyTable = 4242

// policyConfig is route-table enforcement's shape: a table of its own with
// a default into ovl0, throw and unreachable routes, and the rules that
// lead to it.
func policyConfig() netcfg.Config {
	return netcfg.Config{
		Routes: []netcfg.Route{
			{Dst: pfx("0.0.0.0/0"), Interface: "ovl0", Table: policyTable},
			{Dst: pfx("::/0"), Interface: "ovl0", Table: policyTable},
			{Dst: pfx("::/0"), Type: netcfg.RouteUnreachable, Metric: 2048, Table: policyTable},
			{Dst: pfx("10.50.0.0/16"), Type: netcfg.RouteThrow, Table: policyTable},
			{Dst: pfx("fd50::/48"), Type: netcfg.RouteThrow, Table: policyTable},
			{Dst: pfx("10.51.0.0/16"), Interface: "ovl0"},
		},
		Rules: []netcfg.Rule{
			{Family: netcfg.IPv4, Priority: 5300, SuppressDefaultRoutes: true},
			{Family: netcfg.IPv6, Priority: 5300, SuppressDefaultRoutes: true},
			{Family: netcfg.IPv4, Priority: 5299, Dst: pfx("10.51.0.0/16")},
			{Family: netcfg.IPv4, Priority: 5298, Oif: "ovl0", SuppressDefaultRoutes: true},
			{Family: netcfg.IPv6, Priority: 5299, Dst: pfx("fd51::/48")},
			{Family: netcfg.IPv4, Priority: 5301, Table: policyTable, Mark: 0x4242, Invert: true},
			{Family: netcfg.IPv6, Priority: 5301, Table: policyTable, Mark: 0x4242, Invert: true},
		},
	}
}

var policyConfigRoutes = []string{
	"4242 default dev ovl0 metric 0",
	"4242 default dev ovl0 metric 1024",
	"unreachable 4242 default metric 2048",
	"throw 4242 10.50.0.0/16 metric 0",
	"throw 4242 fd50::/48 metric 1024",
	"254 10.51.0.0/16 dev ovl0 metric 0",
}

// ownRules lists the rules carrying an owner's protocol.
func ownRules(t *testing.T, h *netlink.Handle, o netcfg.Owner) []string {
	t.Helper()
	var out []string
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := h.RuleList(fam)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rules {
			if r.Protocol == uint8(o.RouteProtocol()) {
				out = append(out, ruleLine(r))
			}
		}
	}
	slices.Sort(out)
	return out
}

func TestPolicyRoutingIsAppliedAndRemoved(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	n.ip(t, "link", "set", "ovl0", "up")
	before := snapshot(t, n.h)
	c := n.configuratorFor(t, netcfg.OwnerRouteTable)
	ctx := context.Background()
	if err := c.Apply(ctx, policyConfig()); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "routes", policyConfigRoutes, ownerRoutes(t, n.h, netcfg.OwnerRouteTable))
	if got := ownRules(t, n.h, netcfg.OwnerRouteTable); len(got) != 7 {
		t.Fatalf("rules: %q, want 7", got)
	}
	applied := snapshot(t, n.h)
	// The rules do what they say: the table's default for unmarked
	// packets, the main table for marked ones and thrown destinations.
	n.ip(t, "route", "add", "default", "dev", "ovl0", "metric", "500") // a "physical" default in main
	for _, c := range []struct{ args, want string }{
		{"route get 192.0.2.1", "dev ovl0 table 4242"},
		{"route get 192.0.2.1 mark 0x4242", "dev ovl0"},
		{"route get 10.50.1.1", "dev ovl0"},
		{"-6 route get 2001:db8::1", "dev ovl0 table 4242"},
	} {
		out := n.ipOut(t, strings.Fields(c.args)...)
		if !strings.Contains(out, c.want) || (!strings.Contains(c.want, "table") && strings.Contains(out, "table 4242")) {
			t.Errorf("ip %s: %q, want %q", c.args, out, c.want)
		}
	}
	n.ip(t, "route", "del", "default", "dev", "ovl0", "metric", "500")

	if ch := n.changes(t, func() {
		if err := c.Apply(ctx, policyConfig()); err != nil {
			t.Error(err)
		}
	}); ch != 0 {
		t.Errorf("re-applying made %d changes", ch)
	}
	requireSame(t, "after re-applying", applied, snapshot(t, n.h))
	// Nothing is deleted and added back either (a rule the dump reads
	// differently from how it was added would be, every time).
	wctx, stop := context.WithCancel(ctx)
	events, err := c.Watch(wctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Apply(ctx, policyConfig()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-events:
		t.Error("re-applying deleted a route or rule of its own")
	case <-time.After(500 * time.Millisecond):
	}
	stop()

	// Outside changes are repaired; a rule dropped from the config goes.
	n.ip(t, "rule", "del", "priority", "5301")
	n.ip(t, "route", "del", "throw", "10.50.0.0/16", "table", "4242")
	if err := c.Apply(ctx, policyConfig()); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "after repairing", applied, snapshot(t, n.h))
	less := policyConfig()
	less.Rules = less.Rules[:6]
	if err := c.Apply(ctx, less); err != nil {
		t.Fatal(err)
	}
	if got := ownRules(t, n.h, netcfg.OwnerRouteTable); len(got) != 6 {
		t.Errorf("rules after dropping one: %q", got)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "namespace after Close", before, snapshot(t, n.h))
}

func TestCancelledPolicyApplyLeavesNothing(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	n.ip(t, "link", "set", "ovl0", "up")
	before := snapshot(t, n.h)
	c := n.configuratorFor(t, netcfg.OwnerRouteTable)
	left := &atomic.Int32{}
	left.Store(int32(len(policyConfig().Routes) + 5)) // every route and five rules
	err := c.Apply(cancelAfter{context.Background(), left}, policyConfig())
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply: %v, want context.Canceled", err)
	}
	requireSame(t, "namespace after the cancelled Apply", before, snapshot(t, n.h))
}

func TestTakesOverRulesLeftByACrash(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	n.ip(t, "link", "set", "ovl0", "up")
	before := snapshot(t, n.h)
	n.crashAs(t, netcfg.OwnerRouteTable, "policy")
	leftovers := snapshot(t, n.h)
	// Another owner's leftovers are not this one's.
	c := n.configuratorFor(t, netcfg.OwnerOverlay)
	if err := c.Apply(context.Background(), netcfg.Config{}); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "another owner's Apply", leftovers, snapshot(t, n.h))

	rt := n.configuratorFor(t, netcfg.OwnerRouteTable)
	cfg := policyConfig()
	cfg.Rules = cfg.Rules[1:] // one leftover rule is no longer wanted
	if err := rt.Apply(context.Background(), cfg); err != nil {
		t.Fatal(err)
	}
	if got := ownRules(t, n.h, netcfg.OwnerRouteTable); len(got) != 6 {
		t.Errorf("rules after the takeover: %q", got)
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	requireSame(t, "namespace after Close", before, snapshot(t, n.h))
}

func TestWatchSeesGatewayChangesAndOwnRemovals(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	n.dummy(t, "eth0")
	n.ip(t, "link", "set", "ovl0", "up")
	n.ip(t, "link", "set", "eth0", "up")
	n.ip(t, "addr", "add", "192.0.2.2/24", "dev", "eth0")
	c := n.configuratorFor(t, netcfg.OwnerRouteTable)
	if err := c.Apply(context.Background(), policyConfig()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	ch, err := c.Watch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	expect := func(what string, want bool, args ...string) {
		t.Helper()
		// Drain what came before.
		for drained := false; !drained; {
			select {
			case <-ch:
			default:
				drained = true
			}
		}
		n.ip(t, args...)
		select {
		case <-ch:
			if !want {
				t.Errorf("%s: signalled", what)
			}
		case <-time.After(500 * time.Millisecond):
			if want {
				t.Errorf("%s: not signalled", what)
			}
		}
	}
	expect("unrelated route", false, "route", "add", "10.9.0.0/16", "dev", "eth0")
	expect("a default route comes", true, "route", "add", "default", "via", "192.0.2.1")
	expect("the gateway changes", true, "route", "replace", "default", "via", "192.0.2.3")
	expect("our route deleted", true, "route", "del", "10.51.0.0/16")
	expect("our rule deleted", true, "rule", "del", "priority", "5300")
	expect("a foreign rule added", false, "rule", "add", "priority", "6000", "table", "100")
	expect("the default route goes", true, "route", "del", "default")
	expect("a link goes down", true, "link", "set", "eth0", "down")
	expect("a link comes up", true, "link", "set", "eth0", "up")
	expect("an address's on-link route comes", true, "addr", "add", "192.0.3.2/24", "dev", "eth0")
	expect("a link comes", true, "link", "add", "dummy9", "type", "dummy")
	cancel()
	select {
	case _, open := <-ch:
		for open {
			_, open = <-ch
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the channel is still open after ctx ended")
	}
}

// ipOut runs iproute2 in the namespace and returns its output.
func (n *testNS) ipOut(t *testing.T, args ...string) string {
	t.Helper()
	args = append([]string{"-n", strings.TrimPrefix(n.path, "/run/netns/")}, args...)
	out, err := exec.Command("ip", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ip %s: %v: %s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

func TestSurveyFindsOnLinkSubnetsAndForeignRules(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "eth0")
	n.ip(t, "link", "set", "eth0", "up")
	n.ip(t, "addr", "add", "192.0.2.2/24", "dev", "eth0")
	n.ip(t, "addr", "add", "2001:db8:1::2/64", "dev", "eth0", "nodad")
	n.ip(t, "route", "add", "198.51.100.0/24", "dev", "eth0") // a static route: not on-link by an address
	n.ip(t, "rule", "add", "priority", "5210", "table", "52")
	n.ip(t, "-6", "rule", "add", "priority", "5270", "table", "52")
	c := n.configuratorFor(t, netcfg.OwnerRouteTable)
	if err := c.Apply(context.Background(), netcfg.Config{Rules: []netcfg.Rule{{Family: netcfg.IPv4, Priority: 5300, Dst: pfx("192.0.2.0/24")}}}); err != nil {
		t.Fatal(err)
	}
	s, err := c.Survey(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []netip.Prefix{pfx("192.0.2.0/24"), pfx("2001:db8:1::/64"), pfx("fe80::/64")} {
		if !slices.Contains(s.OnLink, want) {
			t.Errorf("on-link %v, want %v among them", s.OnLink, want)
		}
	}
	if !slices.Contains(s.OnLinkInterfaces, "eth0") {
		t.Errorf("on-link interfaces %v, want eth0 among them", s.OnLinkInterfaces)
	}
	if slices.Contains(s.OnLink, pfx("198.51.100.0/24")) {
		t.Errorf("a static route counted as on-link: %v", s.OnLink)
	}
	if !slices.Equal(s.ForeignRules, []int{5210, 5270}) {
		t.Errorf("foreign rules %v, want [5210 5270] (not our 5300, not the kernel's)", s.ForeignRules)
	}
}
