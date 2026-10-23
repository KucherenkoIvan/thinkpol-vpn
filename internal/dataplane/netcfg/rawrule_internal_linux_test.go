//go:build linux && !android

package netcfg

import (
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// rawRuleMsg is a rule message: a fib_rule_hdr, then attributes.
func rawRuleMsg(family, dstLen, action byte, attrs ...[]byte) []byte {
	b := make([]byte, unix.SizeofRtMsg)
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
	// A partial mark mask is a selector netcfg never sets.
	r, err = parseRawRule(rawRuleMsg(unix.AF_INET, 0, unix.FR_ACT_TO_TBL, rta(unix.FRA_FWMARK, u32(0x10)), rta(unix.FRA_FWMASK, u32(0xf0))))
	if err != nil || !r.rule.Other {
		t.Fatalf("a partial mask: %+v, %v", r, err)
	}
}

func TestDumpDone(t *testing.T) {
	if err := dumpDone(u32(0), false); err != nil {
		t.Fatal(err)
	}
	ebusy := -int32(unix.EBUSY)
	if err := dumpDone(u32(uint32(ebusy)), false); !errors.Is(err, unix.EBUSY) {
		t.Fatalf("a failed dump: %v", err)
	}
	if err := dumpDone(nil, true); !errors.Is(err, errDumpInterrupted) {
		t.Fatalf("an interrupted dump: %v", err)
	}
}
