//go:build linux && !android

package netcfg_test

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

func inspectedRoutes(in netcfg.Inspection) []string {
	var out []string
	for _, r := range in.Routes {
		s := fmt.Sprintf("%v %v %s %s table %d metric %d", r.Owner, r.Family, r.Type, r.Dst, r.Table, r.Metric)
		if r.Gateway.IsValid() {
			s += " via " + r.Gateway.String()
		}
		if r.Interface != "" && r.Type == "unicast" {
			s += " dev " + r.Interface
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

func inspectedRules(in netcfg.Inspection) []string {
	var out []string
	for _, r := range in.Rules {
		s := fmt.Sprintf("%v %v %d %s table %d", r.Owner, r.Family, r.Priority, r.Action, r.Table)
		if r.Dst.IsValid() {
			s += " to " + r.Dst.String()
		}
		if r.Oif != "" {
			s += " oif " + r.Oif
		}
		if r.Mark != 0 {
			s += fmt.Sprintf(" fwmark %#x/%#x", r.Mark, r.Mask)
		}
		if r.Invert {
			s += " not"
		}
		if r.SuppressPrefixlen >= 0 {
			s += fmt.Sprintf(" suppress %d", r.SuppressPrefixlen)
		}
		if r.Other {
			s += " other"
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return out
}

// inspectConfig is route-table enforcement's shape, in documentation
// addresses: a table of its own with defaults into ovl0, throw and
// unreachable routes, and the rules that lead to it.
func inspectConfig() netcfg.Config {
	return netcfg.Config{
		Routes: []netcfg.Route{
			{Dst: pfx("0.0.0.0/0"), Interface: "ovl0", Table: policyTable},
			{Dst: pfx("::/0"), Interface: "ovl0", Table: policyTable},
			{Dst: pfx("::/0"), Type: netcfg.RouteUnreachable, Metric: 2048, Table: policyTable},
			{Dst: pfx("198.51.100.0/25"), Type: netcfg.RouteThrow, Table: policyTable},
			{Dst: pfx("2001:db8:d0::/48"), Type: netcfg.RouteThrow, Table: policyTable},
			{Dst: pfx("192.0.2.128/25"), Interface: "ovl0"},
		},
		Rules: []netcfg.Rule{
			{Family: netcfg.IPv4, Priority: 5298, Oif: "ovl0", SuppressDefaultRoutes: true},
			{Family: netcfg.IPv4, Priority: 5299, Dst: pfx("192.0.2.128/25")},
			{Family: netcfg.IPv6, Priority: 5299, Dst: pfx("2001:db8:51::/48")},
			{Family: netcfg.IPv4, Priority: 5300, SuppressDefaultRoutes: true},
			{Family: netcfg.IPv6, Priority: 5300, SuppressDefaultRoutes: true},
			{Family: netcfg.IPv4, Priority: 5301, Table: policyTable, Mark: 0x4242, Invert: true},
			{Family: netcfg.IPv6, Priority: 5301, Table: policyTable, Mark: 0x4242, Invert: true},
		},
	}
}

// TestInspectReadsTheOwnersRoutesAndRules applies route-table
// enforcement's shape for one owner and a route for another, next to
// someone else's routes and rules, and reads them back from the kernel:
// every table, the owners' only, rules with a selector netcfg never sets
// flagged.
func TestInspectReadsTheOwnersRoutesAndRules(t *testing.T) {
	n := newTestNS(t)
	n.dummy(t, "ovl0")
	n.ip(t, "link", "set", "ovl0", "up")
	n.ip(t, "addr", "add", "203.0.113.2/24", "dev", "ovl0")
	empty := netcfg.InspectInNamespace(n.path)
	if empty.RoutesUnreadable != "" || empty.RulesUnreadable != "" || len(empty.Routes) != 0 || len(empty.Rules) != 0 {
		t.Fatalf("nothing applied yet: %+v", empty)
	}

	if err := n.configuratorFor(t, netcfg.OwnerRouteTable).Apply(context.Background(), inspectConfig()); err != nil {
		t.Fatal(err)
	}
	if err := n.configuratorFor(t, netcfg.OwnerOverlay).Apply(context.Background(), netcfg.Config{
		Routes: []netcfg.Route{{Dst: pfx("192.0.2.0/25"), Gateway: addr("203.0.113.1")}},
	}); err != nil {
		t.Fatal(err)
	}
	// Someone else's: a route and a rule of the boot protocol, and a rule
	// with an owner's protocol but an iif, which netcfg never sets.
	n.ip(t, "route", "add", "198.51.100.128/25", "via", "203.0.113.1", "table", "4242")
	n.ip(t, "rule", "add", "priority", "100", "table", "4242")
	n.ip(t, "rule", "add", "priority", "5302", "iif", "ovl0", "table", "4242", "protocol", "86")
	// An owner's rule turned into a blackhole by someone: its action
	// shows, not a lookup.
	n.ip(t, "rule", "add", "priority", "5303", "blackhole", "protocol", "86")
	n.ip(t, "-6", "rule", "add", "priority", "5303", "prohibit", "protocol", "86")
	// Rules sharing a priority and a protocol keep their own actions and
	// selectors; a partial mark mask is a selector netcfg never sets.
	n.ip(t, "rule", "add", "priority", "5304", "to", "198.51.100.0/24", "table", "4242", "protocol", "86")
	n.ip(t, "rule", "add", "priority", "5304", "to", "203.0.113.0/24", "unreachable", "protocol", "86")
	n.ip(t, "rule", "add", "priority", "5305", "fwmark", "0x10/0xf0", "table", "4242", "protocol", "86")

	in := netcfg.InspectInNamespace(n.path)
	if in.RoutesUnreadable != "" || in.RulesUnreadable != "" {
		t.Fatalf("unreadable: %+v", in)
	}
	requireSame(t, "routes", []string{
		"overlay IPv4 unicast 192.0.2.0/25 table 254 metric 0 via 203.0.113.1 dev ovl0",
		"route-table IPv4 throw 198.51.100.0/25 table 4242 metric 0",
		"route-table IPv4 unicast 0.0.0.0/0 table 4242 metric 0 dev ovl0",
		"route-table IPv4 unicast 192.0.2.128/25 table 254 metric 0 dev ovl0",
		"route-table IPv6 throw 2001:db8:d0::/48 table 4242 metric 1024",
		"route-table IPv6 unicast ::/0 table 4242 metric 1024 dev ovl0",
		"route-table IPv6 unreachable ::/0 table 4242 metric 2048",
	}, inspectedRoutes(in))
	requireSame(t, "rules", []string{
		"route-table IPv4 5298 lookup table 254 oif ovl0 suppress 0",
		"route-table IPv4 5299 lookup table 254 to 192.0.2.128/25",
		"route-table IPv4 5300 lookup table 254 suppress 0",
		"route-table IPv4 5301 lookup table 4242 fwmark 0x4242/0xffffffff not",
		"route-table IPv4 5302 lookup table 4242 other",
		"route-table IPv4 5303 blackhole table 0",
		"route-table IPv4 5304 lookup table 4242 to 198.51.100.0/24",
		"route-table IPv4 5304 unreachable table 0 to 203.0.113.0/24",
		"route-table IPv4 5305 lookup table 4242 fwmark 0x10/0xf0 other",
		"route-table IPv6 5299 lookup table 254 to 2001:db8:51::/48",
		"route-table IPv6 5300 lookup table 254 suppress 0",
		"route-table IPv6 5301 lookup table 4242 fwmark 0x4242/0xffffffff not",
		"route-table IPv6 5303 prohibit table 0",
	}, inspectedRules(in))
	for i, r := range in.Rules[1:] {
		if r.Priority < in.Rules[i].Priority {
			t.Fatalf("rules out of order: %v", inspectedRules(in))
		}
	}

	if got := netcfg.InspectInNamespace("/run/netns/no-such-namespace"); !strings.Contains(got.RoutesUnreadable, "no-such-namespace") ||
		got.RulesUnreadable == "" || got.Routes != nil {
		t.Fatalf("a namespace that isn't there: %+v", got)
	}
}
