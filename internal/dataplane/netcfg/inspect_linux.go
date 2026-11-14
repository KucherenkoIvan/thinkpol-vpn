//go:build linux && !android

package netcfg

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"strconv"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sys/unix"
)

// Inspect reads the routes (every table) and policy rules that carry an
// owner's protocol in the calling thread's network namespace.
func Inspect() Inspection {
	// Both sockets must come from one thread's namespace.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	return inspectIn(netns.None())
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
	return inspectIn(ns)
}

// inspectIn reads in ns (netns.None(): the calling thread's).
func inspectIn(ns netns.NsHandle) Inspection {
	var out Inspection
	h, err := netlink.NewHandleAt(ns, unix.NETLINK_ROUTE)
	if err != nil {
		reason := fmt.Sprintf("netlink: %v", err)
		return Inspection{RoutesUnreadable: reason, RulesUnreadable: reason}
	}
	defer h.Close()
	names := linkNames(h)
	for _, fam := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		routes, err := listRoutes(h, fam, &netlink.Route{Table: unix.RT_TABLE_UNSPEC}, netlink.RT_FILTER_TABLE)
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
// from the raw dump: vishvananda/netlink's dump doesn't read a rule's
// action, and pairing its rules with a second dump can't be done safely
// (many rules share a priority and a protocol).
func ownedRules(ns netns.NsHandle) ([]HostRule, error) {
	s, err := newRuleSocket(ns)
	if err != nil {
		return nil, fmt.Errorf("netcfg: list rules: %w", err)
	}
	defer s.Close()
	rules, err := dumpAllRules(s)
	if err != nil {
		return nil, err
	}
	var out []HostRule
	for _, r := range rules {
		if o, ok := ownerOf(r.protocol); ok {
			r.rule.Owner = o
			out = append(out, r.rule)
		}
	}
	slices.SortStableFunc(out, func(a, b HostRule) int { return a.Priority - b.Priority })
	return out, nil
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
