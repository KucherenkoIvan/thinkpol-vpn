package netcfg_test

import (
	"math"
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
		"empty":              {},
		"interface":          ifc(func(*netcfg.Interface) {}),
		"default v4":         route(netcfg.Route{Dst: pfx("0.0.0.0/0"), Gateway: addr("192.0.2.1")}),
		"default v6":         route(netcfg.Route{Dst: pfx("::/0"), Interface: "ovl0"}),
		"metric":             route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Interface: "ovl0", Metric: 5}),
		"link-local gateway": route(netcfg.Route{Dst: pfx("::/0"), Gateway: addr("fe80::1"), Interface: "eth0"}),
		"same dst, other metric": {Routes: []netcfg.Route{
			{Dst: pfx("10.0.0.0/8"), Interface: "ovl0"},
			{Dst: pfx("10.0.0.0/8"), Interface: "ovl0", Metric: 1},
		}},
		"same dst, other table": {Routes: []netcfg.Route{
			{Dst: pfx("10.0.0.0/8"), Interface: "ovl0"},
			{Dst: pfx("10.0.0.0/8"), Interface: "ovl0", Table: 100},
		}},
		"throw":       route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Type: netcfg.RouteThrow, Table: 100}),
		"unreachable": route(netcfg.Route{Dst: pfx("::/0"), Type: netcfg.RouteUnreachable, Table: 300, Metric: 2048}),
		"rules": {Rules: []netcfg.Rule{
			{Family: netcfg.IPv4, Priority: 5300, SuppressDefaultRoutes: true},
			{Family: netcfg.IPv4, Priority: 5301, Table: 300, Mark: 7, Invert: true},
			{Family: netcfg.IPv6, Priority: 5301, Table: 300, Mark: 7, Invert: true},
			{Family: netcfg.IPv4, Priority: 5300, Dst: pfx("192.168.1.0/24")},
			{Family: netcfg.IPv6, Priority: 5300, Dst: pfx("fe80::/64")},
		}},
	}
	for name, c := range valid {
		if err := c.Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	invalid := map[string]netcfg.Config{
		"no name":                              ifc(func(i *netcfg.Interface) { i.Name = "" }),
		"twice":                                {Interfaces: []netcfg.Interface{{Name: "a"}, {Name: "a"}}},
		"negative MTU":                         ifc(func(i *netcfg.Interface) { i.MTU = -1 }),
		"IPv6 below 1280":                      ifc(func(i *netcfg.Interface) { i.MTU = 1200 }),
		"invalid address":                      ifc(func(i *netcfg.Interface) { i.Addrs = append(i.Addrs, netip.Prefix{}) }),
		"4in6 address":                         ifc(func(i *netcfg.Interface) { i.Addrs = []netip.Prefix{pfx("::ffff:10.0.0.1/104")} }),
		"duplicate address":                    ifc(func(i *netcfg.Interface) { i.Addrs = append(i.Addrs, pfx("100.64.0.7/24")) }),
		"unmasked dst":                         route(netcfg.Route{Dst: pfx("10.0.0.1/8"), Interface: "ovl0"}),
		"no gateway or dev":                    route(netcfg.Route{Dst: pfx("10.0.0.0/8")}),
		"mixed families":                       route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Gateway: addr("fd00::1")}),
		"unspecified gw":                       route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Gateway: addr("0.0.0.0")}),
		"negative metric":                      route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Interface: "ovl0", Metric: -1}),
		"metric above 32 bits":                 route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Interface: "ovl0", Metric: int(uint64(math.MaxUint32) + 1)}),
		"zoned gateway":                        route(netcfg.Route{Dst: pfx("::/0"), Gateway: addr("fe80::1%eth0"), Interface: "eth0"}),
		"link-local gateway without interface": route(netcfg.Route{Dst: pfx("::/0"), Gateway: addr("fe80::1")}),
		"throw with a gateway":                 route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Type: netcfg.RouteThrow, Gateway: addr("10.1.1.1")}),
		"unreachable with an interface":        route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Type: netcfg.RouteUnreachable, Interface: "ovl0"}),
		"unknown type":                         route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Interface: "ovl0", Type: 9}),
		"main table by number":                 route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Interface: "ovl0", Table: 254}),
		"local table":                          route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Interface: "ovl0", Table: 255}),
		"negative table":                       route(netcfg.Route{Dst: pfx("10.0.0.0/8"), Interface: "ovl0", Table: -1}),
		"rule without a family":                {Rules: []netcfg.Rule{{Priority: 5300}}},
		"rule at priority 0":                   {Rules: []netcfg.Rule{{Family: netcfg.IPv4}}},
		"rule after main":                      {Rules: []netcfg.Rule{{Family: netcfg.IPv4, Priority: 32766}}},
		"rule in the local table":              {Rules: []netcfg.Rule{{Family: netcfg.IPv4, Priority: 5300, Table: 255}}},
		"rule to another family":               {Rules: []netcfg.Rule{{Family: netcfg.IPv4, Priority: 5300, Dst: pfx("fe80::/64")}}},
		"rule to an unmasked dst":              {Rules: []netcfg.Rule{{Family: netcfg.IPv4, Priority: 5300, Dst: pfx("192.168.1.1/24")}}},
		"rule to /0":                           {Rules: []netcfg.Rule{{Family: netcfg.IPv4, Priority: 5300, Dst: pfx("0.0.0.0/0")}}},
		"rule to ::/0":                         {Rules: []netcfg.Rule{{Family: netcfg.IPv6, Priority: 5300, Dst: pfx("::/0")}}},
		"rule twice":                           {Rules: []netcfg.Rule{{Family: netcfg.IPv6, Priority: 5300}, {Family: netcfg.IPv6, Priority: 5300}}},
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
