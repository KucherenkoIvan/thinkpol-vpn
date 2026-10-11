package lists

import (
	"net/netip"
	"sync"
)

// localPrefixes are the ranges routing rules call `local`: destinations on
// the physical network, which can't usefully go through an exit and hide
// nothing from a censor when they don't.
//
// Not here: 100.64.0.0/10, the overlay's range (the space's own networks
// are decided before any rule, and other CGNAT addresses aren't a LAN);
// loopback, which the OS handles before any route; reserved ranges; and
// ::ffff:0:0/96, since IPv4 is matched as IPv4.
var localPrefixes = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", // LANs
	"169.254.0.0/16",     // link-local
	"224.0.0.0/4",        // multicast: mDNS, SSDP
	"255.255.255.255/32", // limited broadcast: DHCP
	"fe80::/10",          // link-local
	"fc00::/7",           // unique local: LANs
	"ff00::/8",           // multicast
}

// Local is the built-in set of local ranges (LANs, link-local, multicast,
// broadcast), fixed in code rather than downloaded.
var Local = sync.OnceValue(func() *Set {
	var b Builder
	for _, p := range localPrefixes {
		if err := b.AddPrefix(netip.MustParsePrefix(p)); err != nil {
			panic(err)
		}
	}
	s, _ := b.Build()
	return s
})

// All is every address a list can hold: all of IPv4, and all of IPv6 but
// ::ffff:0:0/96 (a mapped address is looked up as IPv4, see
// [Set.Contains]).
var All = sync.OnceValue(func() *Set {
	var b Builder
	for _, r := range [][2]string{
		{"0.0.0.0", "255.255.255.255"},
		{"::", "::fffe:ffff:ffff"},
		{"::1:0:0:0", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"},
	} {
		if err := b.AddRange(netip.MustParseAddr(r[0]), netip.MustParseAddr(r[1])); err != nil {
			panic(err)
		}
	}
	s, _ := b.Build()
	return s
})
