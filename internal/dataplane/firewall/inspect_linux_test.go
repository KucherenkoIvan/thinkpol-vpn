//go:build linux && !android

package firewall_test

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/routetable"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// The guard's rules as InspectIPv6Guard renders them, for TUN thinkpol0
// and mark 0x7470.
var inspectedGuardRules = []string{
	`meta oifname "lo" accept`,
	`meta oifname "thinkpol0" accept`,
	`meta nfproto != ipv6 accept`,
	`meta mark 0x00007470 accept`,
	`@nh,192,128 @exempt6 accept`,
	`meta l4proto ipv6-icmp @th,0,8 133-137 @nh,56,8 255 accept`,
	`meta l4proto ipv6-icmp @th,0,8 130-132 @nh,56,8 1 accept`,
	`meta l4proto ipv6-icmp @th,0,8 143 @nh,56,8 1 accept`,
	`meta l4proto tcp counter reject with tcp reset`,
	`counter reject with icmpx admin-prohibited`,
}

// TestInspectReadsTheGuardAsTheKernelHoldsIt applies the guard, has it
// refuse a bound ping, and reads it back: its chain as hooked, its rules
// in order with the refusal counted, its exempt set as prefixes; a
// dormant table says so; a closed guard is no guard, not an unreadable one.
func TestInspectReadsTheGuardAsTheKernelHoldsIt(t *testing.T) {
	p := newPair(t)
	ns := "/run/netns/" + p.dev
	if r := firewall.InspectIPv6GuardInNamespace(ns); r.Unreadable != "" || r.Present || r.Where != "nftables table inet thinkpol-guard" {
		t.Fatalf("before the guard: %+v", r)
	}
	g := p.guard(t)
	e := routetable.Exempt{TUN: "thinkpol0", Mark: 0x7470, Direct: set(t, "2001:db8:d0::/48", "2001:db8:5::7/128", "198.51.100.0/24")}
	if err := g.Apply(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if p.ping(t, foreign6, "-I", "eth0") {
			t.Fatal("the guard let a bound ping out")
		}
	}

	r := firewall.InspectIPv6GuardInNamespace(ns)
	if r.Unreadable != "" || !r.Present || r.RulesUnreadable != "" || r.ExemptUnreadable != "" || r.PF != nil {
		t.Fatalf("applied: %+v", r)
	}
	if nf := r.NFTables; nf == nil || nf.Dormant || len(nf.Chains) != 1 ||
		nf.Chains[0] != (routetable.NFTChainReport{Name: "output", Hook: "output", Priority: 2147483647, Policy: "accept"}) {
		t.Fatalf("the table: %+v", r.NFTables)
	}
	var texts []string
	for _, rule := range r.Rules {
		texts = append(texts, rule.Text)
		if rule.Chain != "output" || rule.Counted != strings.Contains(rule.Text, "counter") {
			t.Errorf("rule %+v", rule)
		}
	}
	if !slices.Equal(texts, inspectedGuardRules) {
		t.Fatalf("rules:\n%s\nwant:\n%s", strings.Join(texts, "\n"), strings.Join(inspectedGuardRules, "\n"))
	}
	if last := r.Rules[len(r.Rules)-1]; last.Packets < 3 || last.Bytes < 3*64 {
		t.Errorf("three refused pings, counted %d packets, %d bytes", last.Packets, last.Bytes)
	}
	// What the guard exempts: the direct set's IPv6 and the link-scoped
	// ranges, as the fewest prefixes.
	var b lists.Builder
	for _, p := range append([]netip.Prefix{netip.MustParsePrefix("2001:db8:5::7/128"), netip.MustParsePrefix("2001:db8:d0::/48")}, routetable.LinkScoped...) {
		if err := b.AddPrefix(p); err != nil {
			t.Fatal(err)
		}
	}
	all, _ := b.Build()
	want := all.Prefixes()
	if len(want) < 4 || !slices.Equal(r.Exempt, want) {
		t.Fatalf("exempt %v, want %v", r.Exempt, want)
	}

	p.nft(t, "add", "table", "inet", firewall.GuardTable, "{ flags dormant; }")
	if r := firewall.InspectIPv6GuardInNamespace(ns); r.NFTables == nil || !r.NFTables.Dormant {
		t.Fatalf("dormant: %+v\n%s", r.NFTables, p.nft(t, "list", "table", "inet", firewall.GuardTable))
	}

	if err := g.Close(); err != nil {
		t.Fatal(err)
	}
	if r := firewall.InspectIPv6GuardInNamespace(ns); r.Unreadable != "" || r.Present || len(r.Rules) != 0 {
		t.Fatalf("closed: %+v", r)
	}
	if r := firewall.InspectIPv6GuardInNamespace("/run/netns/no-such-namespace"); !strings.Contains(r.Unreadable, "no-such-namespace") {
		t.Fatalf("a namespace that isn't there: %+v", r)
	}
}
