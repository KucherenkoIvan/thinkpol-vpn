//go:build linux && !android

package netcfg

import (
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
)

// A kernel before 4.17 drops a rule's protocol: the rules netcfg adds come
// back without it, and are found as strays (one per rule, a foreign twin
// left alone).
func TestStrayRulesFindRulesThatLostTheirProtocol(t *testing.T) {
	const proto = 86
	kernelRule := func(prio, table int, mark uint32, invert bool, dst string, protocol uint8) netlink.Rule {
		r := *netlink.NewRule()
		r.Family, r.Priority, r.Table, r.Mark, r.Invert, r.Protocol = netlink.FAMILY_V4, prio, table, mark, invert, protocol
		if mark != 0 {
			m := uint32(0xffffffff)
			r.Mask = &m
		}
		if dst != "" {
			_, n, _ := net.ParseCIDR(dst)
			r.Dst = n
		}
		return r
	}
	main := Rule{Family: IPv4, Priority: 5300, Dst: pfx("192.168.1.0/24")}
	tunnel := Rule{Family: IPv4, Priority: 5301, Table: 0x7470, Mark: 0x7470, Invert: true}

	// A current kernel: everything came back with our protocol.
	have := []netlink.Rule{
		kernelRule(5300, 254, 0, false, "192.168.1.0/24", proto),
		kernelRule(5301, 0x7470, 0x7470, true, "", proto),
	}
	if stray := strayRules([]Rule{main, tunnel}, have, proto); len(stray) != 0 {
		t.Errorf("strays on a current kernel: %v", stray)
	}
	// An old kernel: no protocol on either; a foreign twin of one is
	// there too, and only one of the two is taken.
	have = []netlink.Rule{
		kernelRule(5300, 254, 0, false, "192.168.1.0/24", 0),
		kernelRule(5300, 254, 0, false, "192.168.1.0/24", 0),
		kernelRule(5301, 0x7470, 0x7470, true, "", 0),
		kernelRule(32766, 254, 0, false, "", 2),
	}
	stray := strayRules([]Rule{main, tunnel}, have, proto)
	if len(stray) != 2 || stray[0].Priority != 5300 || stray[1].Priority != 5301 {
		t.Errorf("strays on an old kernel: %v", stray)
	}
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
