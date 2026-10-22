//go:build linux && !android

package netcfg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"

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
	out.Rules, err = ownedRules(c, ns)
	if err != nil {
		out.Rules, out.RulesUnreadable = nil, err.Error()
	}
	return out
}

// ownedRules are both families' rules carrying an owner's protocol, with
// their actions, which vishvananda/netlink's dump doesn't read: a second,
// raw dump gives them, by the rules' order; dumps that disagree (the rules
// changed in between) are read again, and then unreadable.
func ownedRules(c *linuxConfigurator, ns netns.NsHandle) ([]HostRule, error) {
	var out []HostRule
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		var rules []netlink.Rule
		var actions []ruleAction
		var err error
		for try := 0; ; try++ {
			if rules, err = c.listRules(fam); err != nil {
				return nil, err
			}
			if actions, err = ruleActions(ns, fam); err != nil {
				return nil, err
			}
			if sameRules(rules, actions) {
				break
			}
			if try == 2 {
				return nil, errors.New("netcfg: the rules changed while they were read")
			}
		}
		for i, r := range rules {
			if o, ok := ownerOf(netlink.RouteProtocol(r.Protocol)); ok {
				hr := hostRule(o, r)
				hr.Action = actionName(actions[i].action)
				out = append(out, hr)
			}
		}
	}
	slices.SortStableFunc(out, func(a, b HostRule) int { return a.Priority - b.Priority })
	return out, nil
}

// ruleAction is what a raw rule dump gives of a rule: its priority and
// protocol, to match it with netlink's, and its action.
type ruleAction struct {
	priority uint32
	protocol uint8
	action   uint8
}

func sameRules(rules []netlink.Rule, actions []ruleAction) bool {
	if len(rules) != len(actions) {
		return false
	}
	for i, r := range rules {
		if uint32(max(r.Priority, 0)) != actions[i].priority || r.Protocol != actions[i].protocol {
			return false
		}
	}
	return true
}

// ruleActions dumps fam's rules in ns: a fib_rule_hdr's action is its
// eighth byte, where an rtmsg has its type. A kernel without the family
// (no IPv6) has none.
func ruleActions(ns netns.NsHandle, fam int) ([]ruleAction, error) {
	s, err := nl.GetNetlinkSocketAt(ns, netns.None(), unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netcfg: list rules: %w", err)
	}
	defer s.Close()
	req := nl.NewNetlinkRequest(unix.RTM_GETRULE, unix.NLM_F_DUMP)
	req.AddData(nl.NewIfInfomsg(fam))
	if err := s.Send(req); err != nil {
		return nil, fmt.Errorf("netcfg: list rules: %w", err)
	}
	var out []ruleAction
	for {
		msgs, _, err := s.Receive()
		if err != nil {
			return nil, fmt.Errorf("netcfg: list rules: %w", err)
		}
		for _, m := range msgs {
			switch m.Header.Type {
			case unix.NLMSG_DONE:
				if m.Header.Flags&unix.NLM_F_DUMP_INTR != 0 {
					return nil, errors.New("netcfg: list rules: the dump was interrupted")
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
				if len(m.Data) < unix.SizeofRtMsg {
					return nil, errors.New("netcfg: list rules: a rule message too short")
				}
				a := ruleAction{action: m.Data[7]}
				attrs, err := nl.ParseRouteAttr(m.Data[unix.SizeofRtMsg:])
				if err != nil {
					return nil, fmt.Errorf("netcfg: list rules: %w", err)
				}
				for _, at := range attrs {
					switch {
					case at.Attr.Type == unix.FRA_PRIORITY && len(at.Value) == 4:
						a.priority = binary.NativeEndian.Uint32(at.Value)
					case at.Attr.Type == unix.FRA_PROTOCOL && len(at.Value) == 1:
						a.protocol = at.Value[0]
					}
				}
				out = append(out, a)
			}
		}
	}
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

func hostRule(o Owner, kr netlink.Rule) HostRule {
	r, plain := ruleOf(kr)
	hr := HostRule{
		Owner: o, Family: r.Family, Priority: kr.Priority, Table: kr.Table, Dst: r.Dst, Oif: kr.OifName,
		Mark: kr.Mark, Invert: kr.Invert, SuppressPrefixlen: kr.SuppressPrefixlen, Other: !plain,
	}
	if kr.Mask != nil {
		hr.Mask = *kr.Mask
	}
	if hr.Family == 0 {
		hr.Family = IPv4
		if kr.Family == netlink.FAMILY_V6 {
			hr.Family = IPv6
		}
	}
	return hr
}
