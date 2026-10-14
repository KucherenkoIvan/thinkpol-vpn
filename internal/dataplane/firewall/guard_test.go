package firewall_test

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

func set(t *testing.T, prefixes ...string) *lists.Set {
	t.Helper()
	var b lists.Builder
	for _, p := range prefixes {
		if err := b.AddPrefix(netip.MustParsePrefix(p)); err != nil {
			t.Fatal(err)
		}
	}
	s, _ := b.Build()
	return s
}

func addr(s string) netip.Addr { return netip.MustParseAddr(s) }

// The guard's exempt destinations are Direct's IPv6 and the link-scoped
// ranges, merged; Direct's IPv4 isn't the IPv6 guard's.
func TestExemptRangesAreIPv6DirectAndLinkScoped(t *testing.T) {
	e := firewall.Exempt{TUN: "thinkpol0", Direct: set(t, "10.0.0.0/8", "2001:db8:d0::/48", "fe80::/64", "fd00::/8")}
	want := []lists.Range{
		{First: addr("2001:db8:d0::"), Last: addr("2001:db8:d0:ffff:ffff:ffff:ffff:ffff")},
		{First: addr("fd00::"), Last: addr("fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		{First: addr("fe80::"), Last: addr("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
		{First: addr("ff02::"), Last: addr("ff02:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
	}
	if got := e.Ranges6(); !slices.Equal(got, want) {
		t.Errorf("Ranges6:\n got %v\nwant %v", got, want)
	}
	// Nothing direct: only the link.
	if got := (firewall.Exempt{TUN: "thinkpol0"}).Ranges6(); len(got) != 2 {
		t.Errorf("Ranges6 with nothing direct: %v", got)
	}
}

func TestExemptEqual(t *testing.T) {
	a := firewall.Exempt{TUN: "thinkpol0", Mark: 0x7470, Direct: set(t, "2001:db8::/32")}
	b := a
	b.Direct = set(t, "2001:db8::/33", "2001:db8:8000::/33")
	if !a.Equal(b) {
		t.Error("the same addresses, built otherwise, aren't equal")
	}
	for _, o := range []firewall.Exempt{
		{TUN: "thinkpol1", Mark: 0x7470, Direct: a.Direct},
		{TUN: "thinkpol0", Direct: a.Direct},
		{TUN: "thinkpol0", Mark: 0x7470},
	} {
		if a.Equal(o) {
			t.Errorf("%+v equals %+v", o, a)
		}
	}
}
