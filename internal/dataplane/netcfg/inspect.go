package netcfg

import (
	"net"
	"net/netip"
	"slices"
)

// Inspection is what the host holds of the owners' routes and rules, as
// its kernel reports them, for diagnostics (`thinkpol diag`): read with
// [Inspect], which changes nothing. A list that couldn't be read says why
// in its Unreadable; one that could is all there is.
type Inspection struct {
	Routes           []HostRoute
	RoutesUnreadable string
	// UnrecordedProto2 are, on macOS, the routes carrying routeFlag
	// (RTF_PROTO2) that no owner's record names (Owner 0): another
	// program's, or an agent's it didn't record.
	UnrecordedProto2 []HostRoute
	Rules            []HostRule
	RulesUnreadable  string
}

// HostRoute is one route an owner holds, as the kernel reports it.
type HostRoute struct {
	Owner  Owner
	Family Family
	Dst    netip.Prefix
	// Type is the kernel's route type: "unicast", "throw", "unreachable",
	// "blackhole", "prohibit" or its number.
	Type      string
	Gateway   netip.Addr
	Interface string
	// Metric and Table are the kernel's (Linux: 254 is main, an IPv6
	// route added with metric 0 has 1024); 0 on macOS.
	Metric int
	Table  int
	// Scope is the interface an RTF_IFSCOPE route is scoped to (macOS).
	Scope string
}

// HostRule is one policy rule an owner holds (Linux), as the kernel
// reports it.
type HostRule struct {
	Owner    Owner
	Family   Family
	Priority int
	// Table is the kernel's table number (254 is main).
	Table int
	Dst   netip.Prefix
	Oif   string
	// Mark and Mask: the firewall mark matched (`fwmark Mark/Mask`).
	Mark, Mask uint32
	Invert     bool
	// SuppressPrefixlen is `suppress_prefixlength`, -1 without one.
	SuppressPrefixlen int
	// Action is what the rule does: "lookup" (in Table), "goto", "nop",
	// "blackhole", "unreachable", "prohibit", or the kernel's number.
	Action string
	// Other: the rule has something netcfg never sets: a selector this
	// doesn't show (an iif, a source, ports...), a partial mark mask, or a
	// suppress_prefixlength other than 0; the action is apart.
	Other bool
}

// InterfaceReport is an interface as the host reports it.
type InterfaceReport struct {
	// Unreadable says why the interface couldn't be read; the rest is
	// then empty.
	Unreadable string
	Name       string
	Index      int
	MTU        int
	// Up and Running are the OS's IFF_UP and IFF_RUNNING.
	Up, Running bool
	// Addrs are its addresses with their prefix lengths, sorted.
	Addrs []netip.Prefix
}

// InspectInterface reads the interface name from the OS, changing
// nothing.
func InspectInterface(name string) InterfaceReport {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return InterfaceReport{Unreadable: err.Error()}
	}
	addrs, err := ifc.Addrs()
	if err != nil {
		return InterfaceReport{Unreadable: err.Error()}
	}
	r := InterfaceReport{
		Name: ifc.Name, Index: ifc.Index, MTU: ifc.MTU,
		Up: ifc.Flags&net.FlagUp != 0, Running: ifc.Flags&net.FlagRunning != 0,
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			ip, ok := netip.AddrFromSlice(n.IP)
			ones, _ := n.Mask.Size()
			if ok {
				r.Addrs = append(r.Addrs, netip.PrefixFrom(ip.Unmap(), ones))
			}
		}
	}
	slices.SortFunc(r.Addrs, func(a, b netip.Prefix) int { return a.Addr().Compare(b.Addr()) })
	return r
}
