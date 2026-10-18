package supervisor

import "net/netip"

// egressBlocked are destinations no space reaches through the root
// namespace, by egress or a dial, unless Options.EgressAllowed names them:
// what is never routed to the internet, link-local networks with the cloud
// metadata services (credentials and the node's own configuration live
// there: 169.254.169.254, AWS's fd00:ec2::254, Azure's 168.63.129.16,
// Alibaba's 100.100.100.200 in 100.64.0.0/10), and the private networks a
// provider may run behind the node (RFC 1918, shared address space, ULA).
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

// EgressRefused says whether the isolation refuses a destination to the
// spaces: it is in egressBlocked and EgressAllowed doesn't name it. The
// node checks a worker resolver's upstreams with it, so the resolver can't
// be given an upstream the spaces' egress would drop.
func EgressRefused(addr netip.Addr, allowed []netip.Prefix) bool {
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
