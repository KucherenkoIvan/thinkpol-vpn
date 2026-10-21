package supervisor

import "net/netip"

// egressBlocked are destinations no space reaches through the root
// namespace, by egress or a dial, unless Options.EgressAllowed names them:
// what is never routed to the internet, the link-local networks with the
// cloud metadata services (EgressNotWorthAllowing names them; credentials
// and the node's own configuration live there), and the private networks
// a provider may run behind the node (RFC 1918, shared address space, ULA).
var egressBlocked = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("168.63.129.16/32"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/3"),
	netip.MustParsePrefix("::/127"),
	netip.MustParsePrefix("::ffff:0:0/96"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// egressNotWorthAllowing are the addresses the refusal hint never
// suggests opening with -egress-allowed: the cloud metadata services
// (AWS's fd00:ec2::254, Azure's 168.63.129.16, Alibaba's 100.100.100.200),
// whose credentials no space should read by any route, and the
// never-routable ranges. Nothing stops an operator from allowing one all
// the same; the hint only never suggests it. The blocked ones are inside
// egressBlocked besides.
var egressNotWorthAllowing = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.100.100.200/32"),
	netip.MustParsePrefix("168.63.129.16/32"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("fd00:ec2::254/128"),
}

// EgressNotWorthAllowing says whether an address the refusal hint never
// suggests opening with -egress-allowed: the metadata services and
// never-routable ranges above, loopback, link-local, multicast, the
// unspecified address, and anything zoned. Nothing stops an operator from
// allowing one of them anyway (Options.EgressAllowed takes any
// prefixes); this only keeps the hint from suggesting it.
func EgressNotWorthAllowing(addr netip.Addr) bool {
	if addr.Zone() != "" || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return true
	}
	for _, p := range egressNotWorthAllowing {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// EgressRefused says whether the egress refuses a destination to the
// spaces: it is in egressBlocked and EgressAllowed doesn't name it. It
// says nothing of the transit ranges, which the supervisor refuses
// besides these.
func EgressRefused(addr netip.Addr, allowed []netip.Prefix) bool {
	if addr.Zone() != "" {
		// A zoned address is scoped to a link of the host's, never a
		// destination through the uplink.
		return true
	}
	for _, p := range allowed {
		if p.Contains(addr) {
			return false
		}
	}
	for _, p := range egressBlocked {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}
