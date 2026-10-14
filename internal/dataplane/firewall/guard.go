package firewall

import (
	"net/netip"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// Exempt is what the IPv6 leak guard lets out of every interface but the
// TUN and loopback while a device is connected; any other IPv6 packet
// leaving there is refused. Routing already sends everything else into
// the TUN (or to an unreachable route): the guard is for what routing
// can't confine, sockets bound to an interface (SO_BINDTODEVICE,
// IPV6_UNICAST_IF, an IPV6_PKTINFO ifindex: `ping -I eth0`, connectivity
// checks, per-link DNS) and other software's routes or tables.
type Exempt struct {
	// TUN is the overlay interface: what leaves through it is the
	// tunnel's.
	TUN string
	// Mark is the links' socket mark (routetable.Mark): the transports'
	// and the direct DNS upstream's sockets, which leave around the
	// tunnel by design. Zero is none.
	Mark uint32
	// Direct are the destinations that leave around the tunnel by the
	// rules (their direct set) and the links' endpoints. Its IPv6 part
	// counts; IPv4 is the kill switch's (TP-048).
	Direct *lists.Set
}

// Equal reports whether e and o exempt the same traffic.
func (e Exempt) Equal(o Exempt) bool {
	return e.TUN == o.TUN && e.Mark == o.Mark && e.Direct.Equal(o.Direct)
}

// LinkScoped are the IPv6 destinations that never leave the link, which
// IPv6 needs to work at all (neighbour discovery, router solicitations,
// DHCPv6, MLD): link-local unicast and link-local multicast. The guard
// always lets them out.
var LinkScoped = []netip.Prefix{
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff02::/16"),
}

// Ranges6 are the IPv6 destinations e lets out of a physical interface
// for any socket: Direct's and LinkScoped, merged.
func (e Exempt) Ranges6() []lists.Range {
	var b lists.Builder
	b.AddSet(e.Direct)
	for _, p := range LinkScoped {
		_ = b.AddPrefix(p) // valid, and outside ::ffff:0:0/96
	}
	s, _ := b.Build()
	var out []lists.Range
	for _, r := range s.Ranges() {
		if r.First.Is6() {
			out = append(out, r)
		}
	}
	return out
}
