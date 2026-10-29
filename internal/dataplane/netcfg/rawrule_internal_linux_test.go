//go:build linux && !android

package netcfg

import (
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// rawRuleMsg is a rule message: a fib_rule_hdr, then attributes.
func rawRuleMsg(family, dstLen, action byte, attrs ...[]byte) []byte {
	b := make([]byte, fibRuleHdrLen)
	b[0], b[1], b[4], b[7] = family, dstLen, 254, action
	for _, a := range attrs {
		b = append(b, a...)
	}
	return b
}

// rta is one attribute, padded to 4 bytes.
func rta(typ uint16, v []byte) []byte {
	b := make([]byte, 4, 4+len(v)+3)
	binary.NativeEndian.PutUint16(b, uint16(4+len(v)))
	binary.NativeEndian.PutUint16(b[2:], typ)
	b = append(b, v...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func u32(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }

func TestParseRawRule(t *testing.T) {
	plain := rawRuleMsg(unix.AF_INET, 25, unix.FR_ACT_TO_TBL,
		rta(unix.FRA_PRIORITY, u32(5299)), rta(unix.FRA_TABLE, u32(254)), rta(unix.FRA_DST, []byte{192, 0, 2, 128}),
		rta(unix.FRA_PROTOCOL, []byte{86}))
	r, err := parseRawRule(plain)
	if err != nil || r.protocol != 86 || r.rule.Other || r.rule.Priority != 5299 || r.rule.Dst.String() != "192.0.2.128/25" || r.rule.Action != "lookup" {
		t.Fatalf("a plain rule: %+v, %v", r, err)
	}
	// An attribute netcfg never sets and this reader doesn't know (a
	// newer kernel's, numbered past them all) marks the rule Other.
	r, err = parseRawRule(append(plain, rta(250, u32(1))...))
	if err != nil || !r.rule.Other {
		t.Fatalf("an unknown attribute: %+v, %v", r, err)
	}
	for name, msg := range map[string][]byte{
		"three bytes":  rawRuleMsg(unix.AF_INET, 24, unix.FR_ACT_TO_TBL, rta(unix.FRA_DST, []byte{192, 0, 2})),
		"/33 for IPv4": rawRuleMsg(unix.AF_INET, 33, unix.FR_ACT_TO_TBL, rta(unix.FRA_DST, []byte{192, 0, 2, 0})),
		"IPv4 in IPv6": rawRuleMsg(unix.AF_INET6, 24, unix.FR_ACT_TO_TBL, rta(unix.FRA_DST, []byte{192, 0, 2, 0})),
	} {
		if _, err := parseRawRule(msg); err == nil || !strings.Contains(err.Error(), "destination") {
			t.Errorf("%s: %v", name, err)
		}
	}
	// A known attribute too short for its value is not read as 0.
	for name, a := range map[string][]byte{
		"a table of two bytes":    rta(unix.FRA_TABLE, []byte{0, 0}),
		"a protocol of two bytes": rta(unix.FRA_PROTOCOL, []byte{86, 0}),
	} {
		r, err = parseRawRule(rawRuleMsg(unix.AF_INET, 0, unix.FR_ACT_TO_TBL, a))
		if err != nil || !r.rule.Other {
			t.Errorf("%s: %+v, %v", name, r, err)
		}
	}
	// A partial mark mask is a selector netcfg never sets.
	r, err = parseRawRule(rawRuleMsg(unix.AF_INET, 0, unix.FR_ACT_TO_TBL, rta(unix.FRA_FWMARK, u32(0x10)), rta(unix.FRA_FWMASK, u32(0xf0))))
	if err != nil || !r.rule.Other {
		t.Fatalf("a partial mask: %+v, %v", r, err)
	}
}

// A dump's error: a kernel without the family's rules (no IPv6) has
// none, an interrupted dump is retried, anything else fails.
func TestDumpErr(t *testing.T) {
	if err := dumpErr(nil); err != nil {
		t.Fatal(err)
	}
	if err := dumpErr(unix.EAFNOSUPPORT); err != nil {
		t.Fatalf("a family the kernel has no rules for: %v", err)
	}
	if err := dumpErr(unix.EBUSY); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("a failed dump: %v", err)
	}
	if err := dumpErr(nl.ErrDumpInterrupted); !errors.Is(err, errDumpInterrupted) {
		t.Fatalf("an interrupted dump: %v", err)
	}
}

// Rule dumps are taken until two in a row hold the same messages, order
// aside: a split dump's repeat is not taken, and rules that never stop
// changing fail.
func TestDumpUntilAgreed(t *testing.T) {
	const proto = 86
	rule := func(prio int) rawRule {
		return rawRule{msg: ruleMsg(Rule{Family: IPv4, Priority: prio}, proto)}
	}
	a, b := rule(5299), rule(5300)
	var dumps int
	from := func(seq ...[]rawRule) func() ([]rawRule, error) {
		dumps = 0
		return func() ([]rawRule, error) {
			i := min(dumps, len(seq)-1)
			dumps++
			return seq[i], nil
		}
	}
	prios := func(rules []rawRule) []int {
		var out []int
		for _, r := range rules {
			kr, err := parseRawRule(r.msg)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, kr.rule.Priority)
		}
		return out
	}

	got, err := dumpUntilAgreed(from([]rawRule{a, b, b}, []rawRule{a, b}, []rawRule{a, b}))
	if err != nil || !slices.Equal(prios(got), []int{5299, 5300}) || dumps != 3 {
		t.Errorf("a repeat, then two alike: %v, %v after %d dumps; want [5299 5300] after 3", prios(got), err, dumps)
	}
	got, err = dumpUntilAgreed(from([]rawRule{a, b}, []rawRule{b, a}))
	if err != nil || len(got) != 2 || dumps != 2 {
		t.Errorf("two alike but for the order: %v, %v after %d dumps; want both rules after 2", prios(got), err, dumps)
	}
	got, err = dumpUntilAgreed(from([]rawRule{}, []rawRule{}))
	if err != nil || len(got) != 0 || dumps != 2 {
		t.Errorf("no rules twice: %v, %v after %d dumps", prios(got), err, dumps)
	}
	alternating := func() ([]rawRule, error) {
		dumps++
		if dumps%2 == 1 {
			return []rawRule{a}, nil
		}
		return []rawRule{a, a}, nil
	}
	dumps = 0
	if got, err := dumpUntilAgreed(alternating); !errors.Is(err, errDumpsDisagree) || got != nil || dumps != dumpRetries {
		t.Errorf("dumps that never agree: %v, %v after %d dumps; want errDumpsDisagree after %d", prios(got), err, dumps, dumpRetries)
	}
	failed := errors.New("a failed dump")
	if _, err := dumpUntilAgreed(func() ([]rawRule, error) { return nil, failed }); !errors.Is(err, failed) {
		t.Errorf("a failed dump: %v", err)
	}
}

// What netcfg adds reads back as the Rule it added, with its protocol:
// every field a Rule has, both families, main and a table past 255.
func TestRuleMsgReadsBackAsTheRule(t *testing.T) {
	const proto = 86
	for _, r := range []Rule{
		{Family: IPv4, Priority: 5300, SuppressDefaultRoutes: true},
		{Family: IPv6, Priority: 5300, SuppressDefaultRoutes: true},
		{Family: IPv4, Priority: 5299, Dst: pfx("192.0.2.0/24")},
		{Family: IPv6, Priority: 5299, Dst: pfx("2001:db8::/48")},
		{Family: IPv4, Priority: 5298, Oif: "ovl0", SuppressDefaultRoutes: true},
		{Family: IPv4, Priority: 5301, Table: 4242, Mark: 0x4242, Invert: true},
		{Family: IPv6, Priority: 5301, Table: 4242, Mark: 0x4242, Invert: true, SuppressDefaultRoutes: true},
		{Family: IPv4, Priority: 1, Table: 100},
	} {
		kr, err := parseRawRule(ruleMsg(r, proto))
		if err != nil {
			t.Fatalf("%v: %v", r, err)
		}
		got, ok := asRule(kr)
		if !ok || got != r || kr.protocol != proto {
			t.Errorf("%v reads back as %v (a Rule: %v), protocol %d", r, got, ok, kr.protocol)
		}
	}
}
