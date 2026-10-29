//go:build linux && !android

package netcfg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Policy rules go through raw RTM_*RULE messages, read and written here:
// vishvananda/netlink's rule dump drops a rule's action, and its delete
// sends none (which matches any).

// fibRuleHdrLen is the size of struct fib_rule_hdr, which starts every
// rule message: family, dst_len, src_len, tos, table, two reserved bytes,
// action, flags.
const fibRuleHdrLen = 12

// rawRule is a rule as the raw dump gives it.
type rawRule struct {
	protocol netlink.RouteProtocol
	// action is the header's (FR_ACT_*): rule.Action is its display name.
	action uint8
	rule   HostRule
	// msg is the rule's message, to delete the rule (or add it back)
	// with every field the kernel holds.
	msg []byte
}

// ruleSocketTimeout bounds each receive on a rule socket: a dump's, or
// the answer to a sendRule.
const ruleSocketTimeout = 5 * time.Second

// newRuleSocket opens a socket for rule dumps and requests in ns
// (netns.None(): the calling thread's, without switching). The socket
// stays in the namespace it was opened in, whatever thread uses it.
func newRuleSocket(ns netns.NsHandle) (*nl.SocketHandle, error) {
	s, err := nl.GetNetlinkSocketAt(ns, netns.None(), unix.NETLINK_ROUTE)
	if err != nil {
		return nil, err
	}
	tv := unix.NsecToTimeval(ruleSocketTimeout.Nanoseconds())
	if err := s.SetReceiveTimeout(&tv); err != nil {
		s.Close()
		return nil, err
	}
	if err := s.SetSendTimeout(&tv); err != nil {
		s.Close()
		return nil, err
	}
	return &nl.SocketHandle{Socket: s}, nil
}

// dumpAllRules dumps both families' rules, one RTM_GETRULE dump per
// family.
func dumpAllRules(s *nl.SocketHandle) ([]rawRule, error) {
	var out []rawRule
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := dumpRules(s, fam)
		if err != nil {
			return nil, err
		}
		out = append(out, rules...)
	}
	return out, nil
}

// dumpRules dumps fam's rules until two dumps in a row agree
// (dumpUntilAgreed). A dump that spans several reads is not consistent:
// the kernel resumes each part at an index into the rule list and never
// sets NLM_F_DUMP_INTR for rules, so a rule inserted ahead of the resume
// point between two parts repeats the rule at the boundary, and one
// deleted ahead skips a rule, without a word. A single dump can therefore
// show one of our rules twice (deleting both copies deletes the only
// rule) or miss one (Close would leave it behind). Two dumps that agree
// mean no such change raced them, unless two changes produced the same
// error twice in a row.
func dumpRules(s *nl.SocketHandle, fam int) ([]rawRule, error) {
	rules, err := dumpUntilAgreed(func() ([]rawRule, error) { return dumpRulesOnce(s, fam) })
	if err != nil {
		return nil, fmt.Errorf("%w (family %d)", err, fam)
	}
	return rules, nil
}

// dumpUntilAgreed takes dumps until two in a row hold the same rule
// messages, order ignored, and returns the last. An interrupted dump
// (should a kernel flag one) agrees with nothing. After dumpRetries dumps
// without agreement it fails with errDumpsDisagree.
func dumpUntilAgreed(dump func() ([]rawRule, error)) ([]rawRule, error) {
	var prev []string // the last whole dump's messages, sorted
	havePrev := false
	for range dumpRetries {
		rules, err := dump()
		if errors.Is(err, errDumpInterrupted) {
			havePrev = false
			continue
		}
		if err != nil {
			return nil, err
		}
		msgs := make([]string, len(rules))
		for i, r := range rules {
			msgs[i] = string(r.msg)
		}
		slices.Sort(msgs)
		if havePrev && slices.Equal(prev, msgs) {
			return rules, nil
		}
		prev, havePrev = msgs, true
	}
	return nil, fmt.Errorf("%w: %d dumps", errDumpsDisagree, dumpRetries)
}

var (
	errDumpInterrupted = errors.New("netcfg: list rules: the dump was interrupted (the rules changed while they were read)")
	errDumpsDisagree   = errors.New("netcfg: list rules: no two dumps in a row agreed (the rules kept changing while they were read)")
)

// dumpRulesOnce dumps fam's rules once. The request is matched to its
// answer by sequence number, so a reply left on the socket by an earlier
// request that timed out is skipped.
func dumpRulesOnce(s *nl.SocketHandle, fam int) ([]rawRule, error) {
	req := nl.NewNetlinkRequest(unix.RTM_GETRULE, unix.NLM_F_DUMP)
	req.Sockets = map[int]*nl.SocketHandle{unix.NETLINK_ROUTE: s}
	hdr := make([]byte, fibRuleHdrLen)
	hdr[0] = byte(fam)
	req.AddRawData(hdr)
	var out []rawRule
	var perr error
	err := req.ExecuteIter(unix.NETLINK_ROUTE, unix.RTM_NEWRULE, func(m []byte) bool {
		r, err := parseRawRule(m)
		if err != nil {
			perr = err
			return false
		}
		out = append(out, r)
		return true
	})
	if err := dumpErr(err); err != nil {
		return nil, err
	}
	if perr != nil {
		return nil, perr
	}
	return out, nil
}

// dumpErr is what a rule dump's error means. EAFNOSUPPORT is a kernel
// without the family's policy rules (booted with ipv6.disable=1, or
// built without IPV6_MULTIPLE_TABLES), which has none: no error. It comes
// in the NLMSG_DONE that ends the dump, or, from older kernels, in an
// NLMSG_ERROR; the netlink library reads the errno from either. A dump
// the kernel interrupted is errDumpInterrupted.
func dumpErr(err error) error {
	switch {
	case err == nil, errors.Is(err, unix.EAFNOSUPPORT):
		return nil
	case errors.Is(err, nl.ErrDumpInterrupted):
		return errDumpInterrupted
	}
	return fmt.Errorf("netcfg: list rules: %w", err)
}

// sendRule sends msg, a rule message (one from the dump, or ruleMsg's),
// as typ (RTM_DELRULE, or RTM_NEWRULE with flags) and waits for the
// kernel's answer. The flags the kernel only reports (a detached
// interface, an unresolved goto) are cleared: an add would keep them.
//
// A delete removes the first rule in the kernel's list that matches every
// field msg sets: its action, protocol, priority, table, and each
// selector it carries. A selector msg doesn't carry (no oif, no mark, no
// destination) matches any value, and the invert flag isn't compared, so
// an earlier rule with the same fields and more can go instead (RR53).
func sendRule(s *nl.SocketHandle, typ, flags int, msg []byte) error {
	if len(msg) < fibRuleHdrLen {
		return errors.New("netcfg: a rule message too short")
	}
	req := nl.NewNetlinkRequest(typ, flags|unix.NLM_F_ACK)
	req.Sockets = map[int]*nl.SocketHandle{unix.NETLINK_ROUTE: s}
	req.AddRawData(withoutReportedFlags(msg))
	_, err := req.Execute(unix.NETLINK_ROUTE, 0)
	return err
}

// withoutReportedFlags is a copy of msg, a rule message at least
// fibRuleHdrLen long, without the flags the kernel only reports (a
// detached iif or oif, an unresolved goto): the message as sendRule sends
// it.
func withoutReportedFlags(msg []byte) []byte {
	body := slices.Clone(msg)
	ruleFlags := binary.NativeEndian.Uint32(body[8:12])
	ruleFlags &^= unix.FIB_RULE_IIF_DETACHED | unix.FIB_RULE_OIF_DETACHED | unix.FIB_RULE_UNRESOLVED
	binary.NativeEndian.PutUint32(body[8:12], ruleFlags)
	return body
}

// ruleMsg is r as netcfg adds it, with proto: the fields parseRawRule
// reads back, so the kernel's copy reads as r again (a mark is sent with
// its whole mask, as the kernel would set it, and the dump reports).
func ruleMsg(r Rule, proto netlink.RouteProtocol) []byte {
	b := make([]byte, fibRuleHdrLen)
	b[0] = unix.AF_INET
	if r.Family == IPv6 {
		b[0] = unix.AF_INET6
	}
	if r.Dst.IsValid() {
		b[1] = byte(r.Dst.Bits())
	}
	b[7] = unix.FR_ACT_TO_TBL
	if r.Invert {
		binary.NativeEndian.PutUint32(b[8:12], unix.FIB_RULE_INVERT)
	}
	u32 := func(v uint32) []byte { return binary.NativeEndian.AppendUint32(nil, v) }
	put := func(typ int, v []byte) { b = append(b, nl.NewRtAttr(typ, v).Serialize()...) }
	put(unix.FRA_PRIORITY, u32(uint32(r.Priority)))
	put(unix.FRA_TABLE, u32(uint32(kernelTable(r.Table))))
	if r.Dst.IsValid() {
		put(unix.FRA_DST, r.Dst.Addr().AsSlice())
	}
	if r.Oif != "" {
		put(unix.FRA_OIFNAME, nl.ZeroTerminated(r.Oif))
	}
	if r.Mark != 0 {
		put(unix.FRA_FWMARK, u32(r.Mark))
		put(unix.FRA_FWMASK, u32(math.MaxUint32))
	}
	if r.SuppressDefaultRoutes {
		put(unix.FRA_SUPPRESS_PREFIXLEN, u32(0))
	}
	put(unix.FRA_PROTOCOL, []byte{uint8(proto)})
	return b
}

// parseRawRule reads a rule message: a fib_rule_hdr and its attributes.
// Only the attributes netcfg sets, or the kernel dumps for every rule,
// are read; any other (a source, an iif, ports, a DSCP of a newer
// kernel...) marks the rule Other, as do a source prefix or TOS in the
// header, a known attribute too short for its value, and anything
// plainRule refuses. A destination that can't be read fails the read.
func parseRawRule(b []byte) (rawRule, error) {
	if len(b) < fibRuleHdrLen {
		return rawRule{}, errors.New("netcfg: list rules: a rule message too short")
	}
	r := HostRule{Family: IPv4, Table: int(b[4]), Action: actionName(b[7]), SuppressPrefixlen: -1,
		Invert: binary.NativeEndian.Uint32(b[8:12])&unix.FIB_RULE_INVERT != 0}
	if b[0] == unix.AF_INET6 {
		r.Family = IPv6
	}
	unknown := b[2] != 0 || b[3] != 0 // src_len, tos
	attrs, err := nl.ParseRouteAttr(b[fibRuleHdrLen:])
	if err != nil {
		return rawRule{}, fmt.Errorf("netcfg: list rules: %w", err)
	}
	out := rawRule{action: b[7], msg: slices.Clone(b)}
	for _, at := range attrs {
		v := at.Value
		u32 := func() uint32 {
			if len(v) < 4 {
				unknown = true
				return 0
			}
			return binary.NativeEndian.Uint32(v)
		}
		switch at.Attr.Type {
		case unix.FRA_PRIORITY:
			r.Priority = int(u32())
		case unix.FRA_TABLE:
			r.Table = int(u32())
		case unix.FRA_DST:
			a, ok := netip.AddrFromSlice(v)
			want := 4
			if r.Family == IPv6 {
				want = 16
			}
			if !ok || len(v) != want || int(b[1]) > 8*want {
				return rawRule{}, fmt.Errorf("netcfg: list rules: a rule's destination of %d bytes, /%d", len(v), b[1])
			}
			r.Dst = netip.PrefixFrom(a, int(b[1]))
		case unix.FRA_OIFNAME:
			r.Oif = strings.TrimRight(string(v), "\x00")
		case unix.FRA_FWMARK:
			r.Mark = u32()
		case unix.FRA_FWMASK:
			r.Mask = u32()
		case unix.FRA_SUPPRESS_PREFIXLEN:
			r.SuppressPrefixlen = int(int32(u32()))
		case unix.FRA_PROTOCOL:
			if len(v) != 1 {
				unknown = true
				break
			}
			out.protocol = netlink.RouteProtocol(v[0])
		default:
			unknown = true
		}
	}
	r.Other = unknown || !plainRule(r)
	out.rule = r
	return out, nil
}

// plainRule says whether r's suppress_prefixlength and mark are ones
// netcfg sets: suppress none or 0, and a mark set whole (mask 0xffffffff)
// or none. The selectors netcfg never sets are parseRawRule's to find;
// the action is apart (asRule judges it).
func plainRule(r HostRule) bool {
	return (r.SuppressPrefixlen == -1 || r.SuppressPrefixlen == 0) &&
		(r.Mark == 0 && r.Mask == 0 || r.Mark != 0 && r.Mask == math.MaxUint32)
}

func actionName(a uint8) string {
	switch a {
	case unix.FR_ACT_TO_TBL:
		return "lookup"
	case unix.FR_ACT_GOTO:
		return "goto"
	case unix.FR_ACT_NOP:
		return "nop"
	case unix.FR_ACT_BLACKHOLE:
		return "blackhole"
	case unix.FR_ACT_UNREACHABLE:
		return "unreachable"
	case unix.FR_ACT_PROHIBIT:
		return "prohibit"
	}
	return strconv.Itoa(int(a))
}
