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

// Inspect reads the routes (every table) and policy rules that carry an
// owner's protocol in the calling thread's network namespace.
func Inspect() Inspection {
	h, err := netlink.NewHandle(unix.NETLINK_ROUTE)
	return inspectWith(h, netns.None(), err)
}

// InspectInNamespace is Inspect in the network namespace at path, without
// entering it.
func InspectInNamespace(path string) Inspection {
	ns, err := netns.GetFromPath(path)
	if err != nil {
		reason := fmt.Sprintf("namespace %s: %v", path, err)
		return Inspection{RoutesUnreadable: reason, RulesUnreadable: reason}
	}
	defer func() { _ = ns.Close() }()
	h, err := netlink.NewHandleAt(ns, unix.NETLINK_ROUTE)
	return inspectWith(h, ns, err)
}

// inspectWith reads through h, in ns (netns.None(): the calling thread's).
func inspectWith(h *netlink.Handle, ns netns.NsHandle, err error) Inspection {
	var out Inspection
	if err != nil {
		reason := fmt.Sprintf("netlink: %v", err)
		return Inspection{RoutesUnreadable: reason, RulesUnreadable: reason}
	}
	defer h.Close()
	names := linkNames(h)
	c := &linuxConfigurator{h: h}
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := c.listRoutes(fam, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
		if err != nil {
			out.Routes, out.RoutesUnreadable = nil, err.Error()
			break
		}
		for _, r := range routes {
			if o, ok := ownerOf(r.Protocol); ok {
				out.Routes = append(out.Routes, hostRoute(o, r, fam, names))
			}
		}
	}
	out.Rules, err = ownedRules(ns)
	if err != nil {
		out.Rules, out.RulesUnreadable = nil, err.Error()
	}
	return out
}

// ownedRules are both families' rules carrying an owner's protocol, read
// from one raw RTM_GETRULE dump per family: vishvananda/netlink's dump
// doesn't read a rule's action, and pairing its rules with a second dump
// can't be done safely (many rules share a priority and a protocol).
func ownedRules(ns netns.NsHandle) ([]HostRule, error) {
	var out []HostRule
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		rules, err := dumpRules(ns, fam)
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			if o, ok := ownerOf(netlink.RouteProtocol(r.protocol)); ok {
				r.rule.Owner = o
				out = append(out, r.rule)
			}
		}
	}
	slices.SortStableFunc(out, func(a, b HostRule) int { return a.Priority - b.Priority })
	return out, nil
}

// rawRule is a rule as the raw dump gives it.
type rawRule struct {
	protocol uint8
	rule     HostRule
}

// ruleDumpTimeout bounds each receive of the raw dump.
const ruleDumpTimeout = 5 * time.Second

// dumpRules dumps fam's rules in ns. A kernel without the family (no
// IPv6) has none; a dump the kernel interrupted (the rules changed
// meanwhile) is taken again, then fails.
func dumpRules(ns netns.NsHandle, fam int) ([]rawRule, error) {
	for try := 0; ; try++ {
		rules, err := dumpRulesOnce(ns, fam)
		if !errors.Is(err, errDumpInterrupted) || try == 2 {
			return rules, err
		}
	}
}

var errDumpInterrupted = errors.New("netcfg: list rules: the dump was interrupted (the rules changed while they were read)")

func dumpRulesOnce(ns netns.NsHandle, fam int) ([]rawRule, error) {
	s, err := nl.GetNetlinkSocketAt(ns, netns.None(), unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netcfg: list rules: %w", err)
	}
	defer s.Close()
	tv := unix.NsecToTimeval(ruleDumpTimeout.Nanoseconds())
	if err := s.SetReceiveTimeout(&tv); err != nil {
		return nil, fmt.Errorf("netcfg: list rules: %w", err)
	}
	req := nl.NewNetlinkRequest(unix.RTM_GETRULE, unix.NLM_F_DUMP)
	req.AddData(nl.NewIfInfomsg(fam))
	if err := s.Send(req); err != nil {
		return nil, fmt.Errorf("netcfg: list rules: %w", err)
	}
	var out []rawRule
	interrupted := false
	for {
		msgs, _, err := s.Receive()
		if err != nil {
			return nil, fmt.Errorf("netcfg: list rules: %w", err)
		}
		for _, m := range msgs {
			interrupted = interrupted || m.Header.Flags&unix.NLM_F_DUMP_INTR != 0
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				if interrupted {
					return nil, errDumpInterrupted
				}
				return out, nil
			case unix.NLMSG_ERROR:
				if len(m.Data) >= 4 {
					if errno := -int32(binary.NativeEndian.Uint32(m.Data)); errno != 0 {
						if unix.Errno(errno) == unix.EAFNOSUPPORT {
							return nil, nil
						}
						return nil, fmt.Errorf("netcfg: list rules: %w", unix.Errno(errno))
					}
				}
			case unix.RTM_NEWRULE:
				r, err := parseRawRule(m.Data)
				if err != nil {
					return nil, err
				}
				out = append(out, r)
			}
		}
	}
}

// parseRawRule reads a rule message: a fib_rule_hdr (family, dst_len,
// src_len, tos, table, two reserved bytes, action, flags) and its
// attributes. A selector or action netcfg never sets marks it Other.
func parseRawRule(b []byte) (rawRule, error) {
	if len(b) < unix.SizeofRtMsg {
		return rawRule{}, errors.New("netcfg: list rules: a rule message too short")
	}
	r := HostRule{Family: IPv4, Table: int(b[4]), Action: actionName(b[7]), SuppressPrefixlen: -1,
		Invert: binary.NativeEndian.Uint32(b[8:12])&unix.FIB_RULE_INVERT != 0, Other: b[2] != 0 || b[3] != 0}
	if b[0] == unix.AF_INET6 {
		r.Family = IPv6
	}
	attrs, err := nl.ParseRouteAttr(b[unix.SizeofRtMsg:])
	if err != nil {
		return rawRule{}, fmt.Errorf("netcfg: list rules: %w", err)
	}
	out := rawRule{}
	maskSeen := false
	for _, at := range attrs {
		v := at.Value
		u32 := func() uint32 {
			if len(v) < 4 {
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
			if a, ok := netip.AddrFromSlice(v); ok {
				if r.Family == IPv4 {
					a = a.Unmap()
				}
				r.Dst = netip.PrefixFrom(a, int(b[1]))
			}
		case unix.FRA_OIFNAME:
			r.Oif = strings.TrimRight(string(v), "\x00")
		case unix.FRA_FWMARK:
			r.Mark = u32()
		case unix.FRA_FWMASK:
			r.Mask, maskSeen = u32(), true
		case unix.FRA_SUPPRESS_PREFIXLEN:
			r.SuppressPrefixlen = int(int32(u32()))
		case unix.FRA_PROTOCOL:
			if len(v) == 1 {
				out.protocol = v[0]
			}
		case unix.FRA_SRC, unix.FRA_IIFNAME, unix.FRA_GOTO, unix.FRA_FLOW, unix.FRA_TUN_ID, unix.FRA_L3MDEV,
			unix.FRA_UID_RANGE, unix.FRA_IP_PROTO, unix.FRA_SPORT_RANGE, unix.FRA_DPORT_RANGE:
			r.Other = true
		case unix.FRA_SUPPRESS_IFGROUP:
			r.Other = r.Other || int32(u32()) != -1
		}
	}
	if r.SuppressPrefixlen != -1 && r.SuppressPrefixlen != 0 {
		r.Other = true
	}
	// netcfg sets a mark whole (mask 0xffffffff) or none.
	whole := r.Mark != 0 && r.Mask == math.MaxUint32
	none := r.Mark == 0 && r.Mask == 0
	if maskSeen && !whole && !none {
		r.Other = true
	}
	out.rule = r
	return out, nil
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

func ownerOf(p netlink.RouteProtocol) (Owner, bool) {
	for _, o := range Owners {
		if p == o.RouteProtocol() {
			return o, true
		}
	}
	return 0, false
}

// linkNames are the namespace's interfaces by index; a link that can't be
// listed shows by its index.
func linkNames(h *netlink.Handle) map[int]string {
	out := map[int]string{}
	links, err := h.LinkList()
	if err != nil && !errors.Is(err, netlink.ErrDumpInterrupted) {
		return out
	}
	for _, l := range links {
		out[l.Attrs().Index] = l.Attrs().Name
	}
	return out
}

func hostRoute(o Owner, r netlink.Route, fam int, names map[int]string) HostRoute {
	hr := HostRoute{Owner: o, Family: IPv4, Dst: dstOf(r, fam), Type: routeType(r.Type), Metric: r.Priority, Table: r.Table}
	if fam == netlink.FAMILY_V6 {
		hr.Family = IPv6
	}
	if a, ok := netip.AddrFromSlice(r.Gw); ok {
		hr.Gateway = a.Unmap()
		if fam == netlink.FAMILY_V6 {
			hr.Gateway = a
		}
	}
	if r.LinkIndex > 0 {
		hr.Interface = names[r.LinkIndex]
		if hr.Interface == "" {
			hr.Interface = "if" + strconv.Itoa(r.LinkIndex)
		}
	}
	return hr
}

func routeType(t int) string {
	switch t {
	case unix.RTN_UNICAST:
		return "unicast"
	case unix.RTN_THROW:
		return "throw"
	case unix.RTN_UNREACHABLE:
		return "unreachable"
	case unix.RTN_BLACKHOLE:
		return "blackhole"
	case unix.RTN_PROHIBIT:
		return "prohibit"
	}
	return strconv.Itoa(t)
}
