package blobs

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/netmap"
)

func TestPlanFrom(t *testing.T) {
	_, ru := geoip(t, "ru", "192.0.2.0/24")
	_, de := geoip(t, "de", "198.51.100.0/24")
	_, by := geoip(t, "by", "203.0.113.0/24")
	unnamed := func(r netmap.BlobRef) netmap.BlobRef { r.Name = ""; return r }
	header := []netmap.BlobRef{unnamed(de), unnamed(ru)}
	wrongSize := by
	wrongSize.SHA256 = ru.SHA256
	wrongSize.Size++

	v4net, v6net := netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("fd00:1::/48")
	a := netip.MustParseAddr
	section := netmap.Section{
		Node: netmap.NodeSettings{
			Kind: netmap.NodeDevice, IPv4: a("100.64.0.2"), IPv6: a("fd00:1::2"), IPv4Network: v4net, IPv6Network: v6net,
		},
		Peers: []netmap.Peer{
			{ID: netmap.NodeID{1}, Addresses: []netip.Addr{a("fd00:1::1"), a("100.64.0.1")}},
			{ID: netmap.NodeID{2}, Addresses: []netip.Addr{a("10.0.0.1"), a("fd00:2::1")}}, // outside the overlay
			{ID: netmap.NodeID{3}, Addresses: []netip.Addr{a("100.64.0.3")}},
		},
		// by isn't in the header; wrongSize names ru with another size.
		Blobs: []netmap.BlobRef{ru, by, wrongSize},
	}

	got := PlanFrom(header, section, true, "tp0")
	want := Plan{
		Want: []netmap.BlobRef{ru},
		Peers: []Peer{
			{ID: netmap.NodeID{1}, Addrs: []netip.Addr{a("100.64.0.1"), a("fd00:1::1")}},
			{ID: netmap.NodeID{3}, Addrs: []netip.Addr{a("100.64.0.3")}},
		},
		Listen:    []netip.Addr{a("100.64.0.2"), a("fd00:1::2")},
		Interface: "tp0",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("device:\n got %+v\nwant %+v", got, want)
	}

	got = PlanFrom(header, section, false, "tp0")
	if got.Listen[0] != a("100.64.0.2") || len(got.Listen) != 1 || len(got.Peers[0].Addrs) != 1 {
		t.Errorf("IPv6 off: %+v", got)
	}

	section.Node.Kind = netmap.NodeServer
	got = PlanFrom(header, section, true, "tp0")
	if !reflect.DeepEqual(got.Want, []netmap.BlobRef{unnamed(de), ru}) {
		t.Errorf("server wants %+v; want the header, ru named", got.Want)
	}
}
