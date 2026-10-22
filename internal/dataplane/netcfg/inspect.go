package netcfg

import "net/netip"

// Inspection is what the host holds of the owners' routes and rules, as
// its kernel reports them, for diagnostics (`thinkpol diag`): read with
// [Inspect], which changes nothing. A list that couldn't be read says why
// in its Unreadable; one that could is all there is.
type Inspection struct {
	Routes           []HostRoute
	RoutesUnreadable string
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
	// Other: the rule has a selector or action netcfg never sets (an
	// iif, a source, a goto...), so this report doesn't show all of it.
	Other bool
}
