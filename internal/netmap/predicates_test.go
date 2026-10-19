package netmap

import (
	"net/netip"
	"strings"
	"testing"
)

// The exported predicates on their boundaries: the limits a map builder
// keeps.
func TestIsOverlayIPv4(t *testing.T) {
	for _, p := range []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
		netip.MustParsePrefix("100.64.0.0/24"),
	} {
		if !IsOverlayIPv4(p) {
			t.Errorf("%v refused", p)
		}
	}
	for _, p := range []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/9"),   // wider than CGNAT
		netip.MustParsePrefix("100.128.0.0/24"), // past its end
		netip.MustParsePrefix("100.64.0.1/16"),  // not masked
	} {
		if IsOverlayIPv4(p) {
			t.Errorf("%v accepted", p)
		}
	}
}

func TestIsOverlayIPv6(t *testing.T) {
	if !IsOverlayIPv6(netip.MustParsePrefix("fd00::/48")) {
		t.Error("fd00::/48 refused")
	}
	for _, p := range []netip.Prefix{
		netip.MustParsePrefix("fc00::/48"), // not in the locally assigned ULA range
		netip.MustParsePrefix("fd00::/56"), // not a /48
		netip.MustParsePrefix("2001:db8::/48"),
	} {
		if IsOverlayIPv6(p) {
			t.Errorf("%v accepted", p)
		}
	}
}

func TestEndsWithDefault(t *testing.T) {
	rule := func(m MatchKind) Rule { return Rule{Match: Match{Kind: m}, Action: Direct} }
	for _, tc := range []struct {
		rules []Rule
		want  bool
	}{
		{nil, true},
		{[]Rule{rule(MatchLocal), rule(MatchDefault)}, true},
		{[]Rule{rule(MatchDefault), rule(MatchLocal)}, false},
	} {
		if got := EndsWithDefault(tc.rules); got != tc.want {
			t.Errorf("EndsWithDefault(%d rules) = %v, want %v", len(tc.rules), got, tc.want)
		}
	}
}

func TestMayLink(t *testing.T) {
	device := &NodeSettings{Kind: NodeDevice}
	server := &NodeSettings{Kind: NodeServer, AllowIngress: true}
	hidden := &NodeSettings{Kind: NodeServer}
	if MayLink(device, hidden) || MayLink(hidden, device) {
		t.Error("a device links to a server with ingress off")
	}
	if !MayLink(device, server) || !MayLink(hidden, hidden) {
		t.Error("a link was refused where one may be")
	}
}

func TestMayEndAChain(t *testing.T) {
	if !(&NodeSettings{Kind: NodeServer, AllowEgress: true}).MayEndAChain() {
		t.Error("a server with egress may not end a chain")
	}
	if (&NodeSettings{Kind: NodeServer}).MayEndAChain() || (&NodeSettings{Kind: NodeDevice, AllowEgress: true}).MayEndAChain() {
		t.Error("a chain ends at a node without egress")
	}
}

// A list or chain name may end with a dash; an overlay name (a DNS label)
// may not.
func TestNameChecks(t *testing.T) {
	for _, ok := range []string{"ru", "ru-", "private", "cloudflare-ipv6", strings.Repeat("a", 32)} {
		if err := CheckListName(ok); err != nil {
			t.Errorf("CheckListName(%q): %v", ok, err)
		}
		if err := CheckChainName(ok); err != nil {
			t.Errorf("CheckChainName(%q): %v", ok, err)
		}
	}
	for _, bad := range []string{"", "RU", "-ru", "r u", "ру", "geolocation-!cn", strings.Repeat("a", 33)} {
		if CheckListName(bad) == nil {
			t.Errorf("CheckListName(%q) accepted", bad)
		}
		if CheckChainName(bad) == nil {
			t.Errorf("CheckChainName(%q) accepted", bad)
		}
	}
	for _, bad := range []string{"", "Home", "-ru", "ru-", "r u", strings.Repeat("a", 64)} {
		if CheckLabel(bad) == nil {
			t.Errorf("CheckLabel(%q) accepted", bad)
		}
	}
}
