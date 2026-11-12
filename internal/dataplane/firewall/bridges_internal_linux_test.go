//go:build linux && !android

package firewall

import (
	"net"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// SetBridgeListing has k's Apply list the bridges with list (nil: the
// namespace's, innerBridges).
func SetBridgeListing(k *KillSwitch, list func(netns int) ([]string, error)) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.listBridges = list
}

// Frames pass bridged within a bridge only when it is on its own: veth
// and tap ports alone, and no default or gatewayed route out of it, of
// either family, in any table.
func TestOnlyBridgesOnTheirOwnPassFramesWithin(t *testing.T) {
	attrs := func(name string, index, master int) netlink.LinkAttrs {
		return netlink.LinkAttrs{Name: name, Index: index, MasterIndex: master}
	}
	links := []netlink.Link{
		&netlink.Bridge{LinkAttrs: attrs("docker0", 10, 0)},
		&netlink.Veth{LinkAttrs: attrs("veth1", 11, 10)},
		&netlink.Veth{LinkAttrs: attrs("veth2", 12, 10)},
		&netlink.Bridge{LinkAttrs: attrs("virbr0", 20, 0)},
		&netlink.Tuntap{LinkAttrs: attrs("vnet0", 21, 20)},
		&netlink.Bridge{LinkAttrs: attrs("empty0", 30, 0)},
		&netlink.Device{LinkAttrs: attrs("eth0", 2, 0)},
	}
	cidr := func(s string) *net.IPNet {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	gw := net.ParseIP("192.0.2.1")
	onLink := []netlink.Route{
		{Type: unix.RTN_UNICAST, LinkIndex: 10, Dst: cidr("172.17.0.0/16")},
		{Type: unix.RTN_UNICAST, LinkIndex: 20, Dst: cidr("2001:db8:20::/64")},
		{Type: unix.RTN_LOCAL, LinkIndex: 10, Dst: cidr("172.17.0.1/32")},
		{Type: unix.RTN_UNICAST, LinkIndex: 2, Gw: gw},
		{Type: unix.RTN_UNREACHABLE, Dst: cidr("0.0.0.0/0"), Table: 0x7470},
	}
	all := []string{"docker0", "empty0", "virbr0"}
	if got := bridgesOnTheirOwn(links, onLink); !slices.Equal(got, all) {
		t.Fatalf("bridges with veth and tap ports and on-link routes: %v, want %v", got, all)
	}
	for _, c := range []struct {
		name   string
		links  []netlink.Link
		routes []netlink.Route
		want   []string
	}{
		{"the uplink enslaved", []netlink.Link{&netlink.Device{LinkAttrs: attrs("eth0", 2, 20)}}, nil, []string{"docker0", "empty0"}},
		{"a dummy port", []netlink.Link{&netlink.Dummy{LinkAttrs: attrs("dummy0", 3, 10)}}, nil, []string{"empty0", "virbr0"}},
		{"an IPv4 default route", nil, []netlink.Route{{Type: unix.RTN_UNICAST, LinkIndex: 20, Gw: gw}}, []string{"docker0", "empty0"}},
		{"an IPv4 default route named 0.0.0.0/0", nil, []netlink.Route{{Type: unix.RTN_UNICAST, LinkIndex: 20, Dst: cidr("0.0.0.0/0"), Gw: gw}}, []string{"docker0", "empty0"}},
		{"an IPv6 default route without a gateway", nil, []netlink.Route{{Type: unix.RTN_UNICAST, LinkIndex: 10, Dst: cidr("::/0")}}, []string{"empty0", "virbr0"}},
		{"a default route in another table", nil, []netlink.Route{{Type: unix.RTN_UNICAST, LinkIndex: 30, Gw: gw, Table: 100}}, []string{"docker0", "virbr0"}},
		{"a route to an entry by a gateway", nil, []netlink.Route{{Type: unix.RTN_UNICAST, LinkIndex: 10, Dst: cidr("203.0.113.50/32"), Gw: net.ParseIP("172.17.0.9")}}, []string{"empty0", "virbr0"}},
		{"a multipath nexthop", nil, []netlink.Route{{Type: unix.RTN_UNICAST, MultiPath: []*netlink.NexthopInfo{{LinkIndex: 2, Gw: gw}, {LinkIndex: 20, Gw: gw}}}}, []string{"docker0", "empty0"}},
		{"a gatewayed route no interface names", nil, []netlink.Route{{Type: unix.RTN_UNICAST, Dst: cidr("198.51.100.0/24"), Gw: gw}}, nil},
	} {
		got := bridgesOnTheirOwn(append(slices.Clone(links), c.links...), append(slices.Clone(onLink), c.routes...))
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}
