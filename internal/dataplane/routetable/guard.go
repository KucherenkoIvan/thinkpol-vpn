package routetable

import (
	"context"
	"errors"
	"net/netip"
	"slices"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// Guard is the firewall half of enforcement, a port the agent fills
// (firewall.IPv6Guard: nftables on Linux, pf on macOS): it refuses on the physical interfaces
// what routing can't keep in the tunnel. An Enforcer opened with one
// applies it after the routes, with the same Want (GuardFor), on every
// Apply and re-apply, re-applies it when Watch says it may have been
// removed, and closes it (removing it) before the routes on Close. A
// fresh Guard's Close removes what a crashed run's left (Clear).
type Guard interface {
	// Apply puts e in place, replacing what the guard held; applying
	// what is in place again checks it is still whole. An error wrapping
	// ErrGuardUnsupported says the OS can't hold it at all.
	Apply(ctx context.Context, e Exempt) error
	// Watch signals when the guard may have been removed or changed
	// from outside (a firewall reload), until ctx ends.
	Watch(ctx context.Context) (<-chan struct{}, error)
	// Close removes the guard; it may be called again after a failure.
	Close() error
}

// ErrGuardUnsupported: the OS can't hold the guard (no nf_tables in the
// kernel; no `anchor "com.apple/*"` in pf's main ruleset); terminal for the
// Enforcer.
var ErrGuardUnsupported = errors.New("routetable: the OS can't hold the leak guard")

// Exempt is what the leak guard lets out of every interface but the TUN
// and loopback while a device is connected; any other IPv6 packet a
// process of the device sends there is refused. Routing already sends
// everything else into the TUN (or to an unreachable route), forwarded
// traffic included (rule 5301): the guard is for locally generated
// traffic routing can't confine, sockets bound to an interface
// (SO_BINDTODEVICE, IPV6_UNICAST_IF, an IPV6_PKTINFO ifindex: `ping -I
// eth0`, connectivity checks, per-link DNS), and other software's routes
// or tables.
type Exempt struct {
	// TUN is the overlay interface: what leaves through it is the
	// tunnel's.
	TUN string
	// Mark is the links' socket mark (Mark): the transports' and the
	// direct DNS upstream's sockets, which leave around the tunnel by
	// design. Zero is none; an OS without socket marks (macOS) ignores
	// it.
	Mark uint32
	// Direct are the destinations that leave around the tunnel by the
	// rules (their direct set) and the links' endpoints. Its IPv6 part
	// counts; IPv4 is the kill switch's (TP-048).
	Direct *lists.Set
	// Upstreams are the direct DNS upstreams the agent's resolver asks
	// (Want.Upstreams): for an OS without socket marks (macOS's pf),
	// where Mark can't exempt them. Linux's guard leaves them to Mark.
	Upstreams []netip.Addr
}

// Equal reports whether e and o exempt the same traffic.
func (e Exempt) Equal(o Exempt) bool {
	return e.TUN == o.TUN && e.Mark == o.Mark && e.Direct.Equal(o.Direct) &&
		slices.Equal(bypass(e.Upstreams), bypass(o.Upstreams))
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

// GuardFor is what the guard lets out around the tunnel for w: exactly
// what the table throws (the direct destinations and the endpoints), the
// links' marked sockets, and w's direct DNS upstreams, the same ones the
// table routes (Want.Upstreams): one source for both.
func GuardFor(w Want) Exempt {
	var b lists.Builder
	b.AddSet(w.Direct)
	for _, a := range bypass(w.Bypass) {
		_ = b.AddPrefix(netip.PrefixFrom(a, a.BitLen())) // an IPv4-mapped endpoint was unmapped
	}
	direct, _ := b.Build()
	return Exempt{TUN: w.TUN, Mark: Mark, Direct: direct, Upstreams: bypass(w.Upstreams)}
}
