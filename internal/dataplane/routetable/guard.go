package routetable

import (
	"context"
	"net/netip"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/firewall"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// Guard is the firewall half of enforcement: what routing can't confine
// (sockets bound to an interface, other software's routes), refused on
// the physical interfaces. An Enforcer applies it after the routes, with
// the same Want (GuardFor), on every Apply and re-Apply, and removes it
// on Close; Clear removes what a crash left. firewall.IPv6Guard on
// Linux; none elsewhere yet (newGuard).
type Guard interface {
	Apply(ctx context.Context, e firewall.Exempt) error
	Close() error
}

// GuardFor is what the guard lets out around the tunnel for w: exactly
// what the table throws (the direct destinations and the endpoints) and
// the links' marked sockets.
func GuardFor(w Want) firewall.Exempt {
	var b lists.Builder
	b.AddSet(w.Direct)
	for _, a := range bypass(w.Bypass) {
		_ = b.AddPrefix(netip.PrefixFrom(a, a.BitLen())) // an IPv4-mapped endpoint was unmapped
	}
	direct, _ := b.Build()
	return firewall.Exempt{TUN: w.TUN, Mark: Mark, Direct: direct}
}
