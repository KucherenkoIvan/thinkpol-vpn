//go:build linux && !android

package netcfg

import (
	"errors"
	"net/netip"
	"slices"
	"testing"

	"github.com/vishvananda/netlink"
)

// A kernel before 4.17 drops a rule's protocol: the rules netcfg adds come
// back without it, and are found as strays (one per rule, a foreign twin
// left alone).
func TestStrayRulesFindRulesThatLostTheirProtocol(t *testing.T) {
	const proto = 86
	// The rules as parseRawRule reads them: strayRules takes the raw
	// dump's.
	kernelRule := func(prio, table int, mark uint32, invert bool, dst string, protocol netlink.RouteProtocol) rawRule {
		r := HostRule{Family: IPv4, Priority: prio, Table: table, Mark: mark, Invert: invert, SuppressPrefixlen: -1, Action: "lookup"}
		if mark != 0 {
			r.Mask = 0xffffffff
		}
		if dst != "" {
			r.Dst = pfx(dst)
		}
		return rawRule{protocol: protocol, rule: r}
	}
	main := Rule{Family: IPv4, Priority: 5300, Dst: pfx("192.168.1.0/24")}
	tunnel := Rule{Family: IPv4, Priority: 5301, Table: 0x7470, Mark: 0x7470, Invert: true}

	// A current kernel: everything came back with our protocol.
	have := []rawRule{
		kernelRule(5300, 254, 0, false, "192.168.1.0/24", proto),
		kernelRule(5301, 0x7470, 0x7470, true, "", proto),
	}
	if stray := strayRules([]Rule{main, tunnel}, have, proto); len(stray) != 0 {
		t.Errorf("strays on a current kernel: %v", stray)
	}
	// An old kernel: no protocol on either; a foreign twin of one is
	// there too, and only one of the two is taken.
	have = []rawRule{
		kernelRule(5300, 254, 0, false, "192.168.1.0/24", 0),
		kernelRule(5300, 254, 0, false, "192.168.1.0/24", 0),
		kernelRule(5301, 0x7470, 0x7470, true, "", 0),
		kernelRule(32766, 254, 0, false, "", 2),
	}
	stray := strayRules([]Rule{main, tunnel}, have, proto)
	if len(stray) != 2 || stray[0].rule.Priority != 5300 || stray[1].rule.Priority != 5301 {
		t.Errorf("strays on an old kernel: %v", stray)
	}
}

// A rule just added that the kernel holds with our protocol but that
// reads back as something netcfg doesn't add (here an attribute
// parseRawRule doesn't read) fails, rather than be replaced by every
// Apply; one that reads back as added passes.
func TestJudgeAddedFailsARuleThatDoesNotReadBack(t *testing.T) {
	const proto = 86
	r := Rule{Family: IPv4, Priority: 5299, Dst: pfx("192.0.2.0/24")}
	msg := ruleMsg(r, proto)
	added, err := parseRawRule(msg)
	if err != nil {
		t.Fatal(err)
	}
	if stray, err := judgeAdded([]Rule{r}, []rawRule{added}, proto); stray != nil || err != nil {
		t.Fatalf("a rule read back as added: %v, %v", stray, err)
	}
	other, err := parseRawRule(append(slices.Clone(msg), rta(250, u32(1))...))
	if err != nil {
		t.Fatal(err)
	}
	if stray, err := judgeAdded([]Rule{r}, []rawRule{other}, proto); stray != nil || !errors.Is(err, errNotReadBack) {
		t.Fatalf("a rule read back with an unknown attribute: %v, %v", stray, err)
	}
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
