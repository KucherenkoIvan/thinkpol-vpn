package netcfg_test

import (
	"net/netip"
	"testing"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
)

func TestValidate(t *testing.T) {
	ifc := func(mod func(*netcfg.Interface)) netcfg.Config {
		i := netcfg.Interface{Name: "ovl0", Addrs: []netip.Prefix{pfx("100.64.0.7/10"), pfx("fd12:3456:789a::7/48")}, MTU: 1380}
		mod(&i)
		return netcfg.Config{Interfaces: []netcfg.Interface{i}}
	}
	route := func(r netcfg.Route) netcfg.Config { return netcfg.Config{Routes: []netcfg.Route{r}} }
	valid := map[string]netcfg.Config{
		"empty":            {},
		"interface":        ifc(func(*netcfg.Interface) {}),
		"default v4":       route(netcfg.Route{Dst: pfx("0.0.0.0/0"), Gateway: addr("192.0.2.1")}),
		"default v6":       route(netcfg.Route{Dst: pfx("::/0"), Interface: "ovl0"}),
		"table and metric": route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Interface: "ovl0", Table: 100, Metric: 5}),
		"same dst, other metric": {Routes: []netcfg.Route{
			{Dst: pfx("10.0.0.0/8"), Interface: "ovl0"},
			{Dst: pfx("10.0.0.0/8"), Interface: "ovl0", Metric: 1},
		}},
	}
	for name, c := range valid {
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	invalid := map[string]netcfg.Config{
		"no name":           ifc(func(i *netcfg.Interface) { i.Name = "" }),
		"twice":             {Interfaces: []netcfg.Interface{{Name: "a"}, {Name: "a"}}},
		"negative MTU":      ifc(func(i *netcfg.Interface) { i.MTU = -1 }),
		"IPv6 below 1280":   ifc(func(i *netcfg.Interface) { i.MTU = 1200 }),
		"invalid address":   ifc(func(i *netcfg.Interface) { i.Addrs = append(i.Addrs, netip.Prefix{}) }),
		"4in6 address":      ifc(func(i *netcfg.Interface) { i.Addrs = []netip.Prefix{pfx("::ffff:10.0.0.1/104")} }),
		"duplicate address": ifc(func(i *netcfg.Interface) { i.Addrs = append(i.Addrs, pfx("100.64.0.7/24")) }),
		"unmasked dst":      route(netcfg.Route{Dst: pfx("10.0.0.1/8"), Interface: "ovl0"}),
		"no gateway or dev": route(netcfg.Route{Dst: pfx("10.0.0.0/8")}),
		"mixed families":    route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Gateway: addr("fd00::1")}),
		"unspecified gw":    route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Gateway: addr("0.0.0.0")}),
		"negative table":    route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Interface: "ovl0", Table: -1}),
		"duplicate identity": {Routes: []netcfg.Route{
			{Dst: pfx("10.0.0.0/8"), Interface: "ovl0"},
			{Dst: pfx("10.0.0.0/8"), Gateway: addr("10.1.1.1")},
		}},
	}
	for name, c := range invalid {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: valid, want an error", name)
		}
	}
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
func addr(s string) netip.Addr  { return netip.MustParseAddr(s) }
