//go:build linux && !android

package firewall_test

import (
	"context"
	"fmt"
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
	// A table without the set (someone else's, or half made) exempts
	// nothing: not there, not unreadable.
	p.nft(t, "add", "table", "inet", firewall.GuardTable)
	if r := firewall.InspectIPv6GuardInNamespace(ns); !r.Present || r.ExemptUnreadable != "" || r.Exempt != nil || r.NFTables.ChainsUnreadable != "" || len(r.Rules) != 0 {
		t.Fatalf("a table without its set: %+v", r)
	}
	p.nft(t, "delete", "table", "inet", firewall.GuardTable)
	if r := firewall.InspectIPv6GuardInNamespace(ns); r.Unreadable != "" || r.Present || len(r.Rules) != 0 {
		t.Fatalf("closed: %+v", r)
	}
	if r := firewall.InspectIPv6GuardInNamespace("/run/netns/no-such-namespace"); !strings.Contains(r.Unreadable, "no-such-namespace") {
		t.Fatalf("a namespace that isn't there: %+v", r)
	}
}

// TestInspectReadsTheKillSwitchAsTheKernelHoldsIt applies the kill switch
// down, has it refuse pings, and reads it back: its two chains as hooked,
// its rules in nft's order (the forward chain's replies by conntrack's
// direction) with the refusals counted, its sets' sizes; connected, the
// TUN's rules and the direct sets' sizes; closed, no kill switch, not an
// unreadable one.
func TestInspectReadsTheKillSwitchAsTheKernelHoldsIt(t *testing.T) {
	p := ksPair(t)
	ns := "/run/netns/" + p.dev
	if r := firewall.InspectKillSwitchInNamespace(ns); r.Unreadable != "" || r.Present || r.Rules != nil || r.Sets != nil ||
		r.Where != "nftables table inet thinkpol-killswitch" {
		t.Fatalf("before the kill switch: %+v", r)
	}
	k := p.killSwitch(t)
	ctx := context.Background()
	down := firewall.KillSwitchRules{Mark: routetable.Mark, Allow: set(t, entry4+"/32", entry6+"/128", "10.0.0.0/8"), NoDNS: set(t, "10.0.0.0/8")}
	if err := k.Apply(ctx, down); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if p.ping4(t, foreign4) {
			t.Fatal("the kill switch let a ping out")
		}
	}

	r := firewall.InspectKillSwitchInNamespace(ns)
	if r.Unreadable != "" || !r.Present || r.PresentUnknown || r.RulesUnreadable != "" || r.SetsUnreadable != "" || r.PF != nil {
		t.Fatalf("down: %+v", r)
	}
	wantChains := []routetable.NFTChainReport{
		{Name: "output", Hook: "output", Priority: 2147483647, Policy: "accept"},
		{Name: "forward", Hook: "forward", Priority: 2147483647, Policy: "accept"},
	}
	if nf := r.NFTables; nf == nil || nf.Dormant || nf.ChainsUnreadable != "" || !slices.Equal(nf.Chains, wantChains) {
		t.Fatalf("the table: %+v", r.NFTables)
	}
	perChain := map[string]int{}
	var texts []string
	for _, rule := range r.Rules {
		perChain[rule.Chain]++
		texts = append(texts, rule.Chain+": "+rule.Text)
		if rule.Counted != strings.Contains(rule.Text, "counter") {
			t.Errorf("rule %+v", rule)
		}
	}
	for _, chain := range []string{"output", "forward"} {
		if n := ruleLines(p.nft(t, "-a", "list", "chain", "inet", firewall.KillSwitchTable, chain)); perChain[chain] != n || n < 5 {
			t.Errorf("chain %s: %d rules, nft lists %d", chain, perChain[chain], n)
		}
	}
	for _, want := range []string{
		`output: meta oifname "lo" accept`,
		`output: meta mark 0x00007470 accept`,
		"output: counter reject with icmpx admin-prohibited",
		"forward: ct direction reply meta nfproto ipv4 @nh,96,32 @allow4 accept",
	} {
		if !slices.Contains(texts, want) {
			t.Errorf("no rule %q in:\n%s", want, strings.Join(texts, "\n"))
		}
	}
	if slices.ContainsFunc(texts, func(s string) bool { return strings.Contains(s, "thinkpol0") }) {
		t.Errorf("down, the TUN passes:\n%s", strings.Join(texts, "\n"))
	}
	if last := r.Rules[perChain["output"]-1]; last.Chain != "output" || last.Packets < 3 {
		t.Errorf("three refused pings, the output chain's last rule counted %+v", last)
	}
	if got, want := setSizes(r.Sets), "allow4=2 allow6=1 direct4=0 direct6=0 nodns4=1 nodns6=0"; got != want {
		t.Errorf("sets %s, want %s", got, want)
	}

	up := down
	up.TUN, up.Direct = "thinkpol0", set(t, "198.51.100.0/24", "192.0.2.0/25", "192.0.2.200/32", "2001:db8:d0::/48")
	if err := k.Apply(ctx, up); err != nil {
		t.Fatal(err)
	}
	r = firewall.InspectKillSwitchInNamespace(ns)
	texts = nil
	for _, rule := range r.Rules {
		texts = append(texts, rule.Chain+": "+rule.Text)
	}
	for _, want := range []string{`output: meta oifname "thinkpol0" accept`, `forward: meta iifname "thinkpol0" accept`} {
		if !slices.Contains(texts, want) {
			t.Errorf("connected: no rule %q in:\n%s", want, strings.Join(texts, "\n"))
		}
	}
	if got, want := setSizes(r.Sets), "allow4=2 allow6=1 direct4=3 direct6=1 nodns4=1 nodns6=0"; got != want {
		t.Errorf("connected: sets %s, want %s", got, want)
	}

	if err := k.Close(); err != nil {
		t.Fatal(err)
	}
	if r := firewall.InspectKillSwitchInNamespace(ns); r.Unreadable != "" || r.Present || r.Rules != nil || r.Sets != nil || r.NFTables != nil {
		t.Fatalf("closed: %+v", r)
	}
	if r := firewall.InspectKillSwitchInNamespace("/run/netns/no-such-namespace"); !strings.Contains(r.Unreadable, "no-such-namespace") {
		t.Fatalf("a namespace that isn't there: %+v", r)
	}
}

// setSizes is sets as "name=entries ...", by name; an unreadable one
// as "name=?".
func setSizes(sets []firewall.KillSwitchSetReport) string {
	var out []string
	for _, s := range sets {
		n := fmt.Sprint(s.Entries)
		if s.Unreadable != "" {
			n = "?"
		}
		out = append(out, s.Name+"="+n)
	}
	slices.Sort(out)
	return strings.Join(out, " ")
}

// ruleLines counts the rules in `nft -a list chain`'s output: the lines
// with a handle that open no block (the table's and the chain's lines
// have one too).
func ruleLines(listed string) int {
	n := 0
	for _, l := range strings.Split(listed, "\n") {
		if strings.Contains(l, "# handle") && !strings.Contains(l, "{") {
			n++
		}
	}
	return n
}
