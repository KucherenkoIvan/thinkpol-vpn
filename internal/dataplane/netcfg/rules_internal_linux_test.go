//go:build linux && !android

package netcfg

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"syscall"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
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
		return rawRule{protocol: protocol, action: unix.FR_ACT_TO_TBL, rule: r}
	}
	main := Rule{Family: IPv4, Priority: 5300, Dst: pfx("192.168.1.0/24")}
	tunnel := Rule{Family: IPv4, Priority: 5301, Table: 0x7470, Mark: 0x7470, Invert: true}

	// A current kernel: everything came back with our protocol.
	have := []rawRule{
		kernelRule(5300, 254, 0, false, "192.168.1.0/24", proto),
		kernelRule(5301, 0x7470, 0x7470, true, "", proto),
	}
	if stray := strayRules([]Rule{main, tunnel}, have, rulesWith(have, proto), proto); len(stray) != 0 {
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
	stray := strayRules([]Rule{main, tunnel}, have, rulesWith(have, proto), proto)
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
	// A kernel before 4.17 holds it without the protocol: a stray to
	// delete, and a kernel netcfg can't put rules on.
	old, err := parseRawRule(ruleMsg(r, 0))
	if err != nil {
		t.Fatal(err)
	}
	stray, err := judgeAdded([]Rule{r}, []rawRule{old}, proto)
	if len(stray) != 1 || !bytes.Equal(stray[0].msg, old.msg) || !errors.Is(err, errOldKernel) {
		t.Fatalf("a rule read back without its protocol: %v, %v", stray, err)
	}
}

// Our rules sorted against want: one decision per distinct message, the
// flags the kernel only reports aside.
func TestSurplusRules(t *testing.T) {
	const proto = 86
	read := func(msg []byte) rawRule {
		t.Helper()
		kr, err := parseRawRule(msg)
		if err != nil {
			t.Fatal(err)
		}
		return kr
	}
	kept := Rule{Family: IPv4, Priority: 5299, Dst: pfx("192.0.2.0/24")}
	keptOif := Rule{Family: IPv4, Priority: 5298, Oif: "ovl0", SuppressDefaultRoutes: true}
	unwanted := Rule{Family: IPv4, Priority: 5300, SuppressDefaultRoutes: true}
	msg := ruleMsg(kept, proto)
	// keptOif's repeat in a split dump, its oif gone between the two
	// parts: the kernel flags it detached, but it is the same rule.
	detached := ruleMsg(keptOif, proto)
	binary.NativeEndian.PutUint32(detached[8:12], unix.FIB_RULE_OIF_DETACHED)
	blackhole := slices.Clone(msg)
	blackhole[7] = unix.FR_ACT_BLACKHOLE
	// A second message that reads as kept, another rule as far as the
	// bytes go. A kernel writes attributes in one order, so its dump
	// can't hold this pair; it stands for any such pair. Deleting it is
	// harmless: the delete may take either copy, and the one left reads
	// as kept.
	twin := rawRuleMsg(unix.AF_INET, 24, unix.FR_ACT_TO_TBL, rta(unix.FRA_PROTOCOL, []byte{proto}),
		rta(unix.FRA_DST, []byte{192, 0, 2, 0}), rta(unix.FRA_TABLE, u32(unix.RT_TABLE_MAIN)), rta(unix.FRA_PRIORITY, u32(5299)))
	have := []rawRule{read(blackhole), read(msg), read(ruleMsg(unwanted, proto)), read(ruleMsg(keptOif, proto)),
		read(msg), read(detached), read(ruleMsg(unwanted, proto)), read(twin)}
	present, surplus := surplusRules([]Rule{kept, keptOif}, have)
	if !present[kept] || !present[keptOif] || len(present) != 2 {
		t.Errorf("present: %v, want only %v and %v", present, kept, keptOif)
	}
	var got []string
	for _, kr := range surplus {
		got = append(got, fmt.Sprintf("%v %v", kr.rule.Action, kr.rule.Priority))
	}
	if want := []string{"blackhole 5299", "lookup 5300", "lookup 5299"}; !slices.Equal(got, want) {
		t.Errorf("surplus %q, want %q", got, want)
	}
	if len(surplus) == 3 && !bytes.Equal(surplus[2].msg, twin) {
		t.Errorf("the last surplus rule is not the twin: %v", surplus[2].msg)
	}
}

// A rule deleted matters when it carried our protocol, or can't be read.
func TestRelevantRuleDeletes(t *testing.T) {
	const proto = 86
	c := &linuxConfigurator{proto: proto}
	r := Rule{Family: IPv4, Priority: 5299, Dst: pfx("192.0.2.0/24")}
	del := func(data []byte) syscall.NetlinkMessage {
		return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: unix.RTM_DELRULE}, Data: data}
	}
	for name, tc := range map[string]struct {
		data []byte
		want bool
	}{
		"ours":       {ruleMsg(r, proto), true},
		"another's":  {ruleMsg(r, proto+1), false},
		"unreadable": {rawRuleMsg(unix.AF_INET, 24, unix.FR_ACT_TO_TBL, rta(unix.FRA_DST, []byte{192, 0, 2})), true},
		"too short":  {[]byte{unix.AF_INET, 0, 0, 0}, true},
	} {
		if got := c.relevant(del(tc.data)); got != tc.want {
			t.Errorf("%s: relevant %v, want %v", name, got, tc.want)
		}
	}
}

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }
