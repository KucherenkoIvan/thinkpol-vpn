package routetable

import (
	"net/netip"
	"runtime"
	"slices"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// Layout is a Want laid out for this OS's routing, against a Survey:
// policy routing on Linux (PolicyRouting), split routes in the main table
// on macOS (SplitRoutes).
type Layout struct {
	Config netcfg.Config
	// Ahead counts what other software has in place that may route
	// traffic around the tunnel and the layout can't override: on Linux,
	// policy rules ahead of the tunnel's; on macOS, foreign host routes
	// over tunneled destinations (see SplitRoutes).
	Ahead int
	// OverlayAhead counts foreign host routes inside the overlay's
	// networks that nothing can outrank (macOS: a DHCP server's classless
	// host route to a peer's overlay address), which take that peer's
	// traffic out of the tunnel in the clear. Linux looks the overlay up
	// in a table of its own: always zero there.
	OverlayAhead int
}

// LayoutOf lays w out against s, once per apply.
func LayoutOf(w Want, s netcfg.Survey) Layout {
	if runtime.GOOS == "darwin" {
		cfg, ahead, overlayAhead := splitRoutes(w, s)
		return Layout{Config: cfg, Ahead: ahead, OverlayAhead: overlayAhead}
	}
	return Layout{Config: PolicyRouting(w, s), Ahead: rulesAhead(s)}
}

// rulesAhead counts the foreign policy rules ahead of the tunnel's.
func rulesAhead(s netcfg.Survey) int {
	n := 0
	for _, p := range s.ForeignRules {
		if p < PriorityTunnel {
			n++
		}
	}
	return n
}

// SplitRoutes is w as routes in the main table, for an OS without policy
// routing (macOS), where every route competes by prefix length alone:
//
//	0.0.0.0/1, 128.0.0.0/1          -interface <TUN>   (reject while the TUN is down)
//	::/2, 4000::/2, 8000::/2, c000::/2  -interface <TUN>   (while the TUN is up and carries IPv6)
//	::/1, 8000::/1                  reject             (always: behind the TUN's, and alone without IPv6)
//	<direct prefix>, <endpoint>     via <the family's default gateway>
//	<shadow>                        -interface <TUN> (or reject, like its family)
//
// The OS's default routes stay as they are, so the split routes beat them
// without naming the gateway; direct destinations and endpoints name it,
// and Survey's Defaults change when the network does (the Enforcer's
// watcher re-applies). IPv6 always has a reject route behind the TUN's,
// so when the TUN goes (a crash takes its routes along) IPv6 stays
// blocked but for direct destinations until the next start, as on Linux;
// IPv4 then follows the physical default route (D4's kill switch off).
// The overlay's networks are routed into the TUN by the overlay's own
// configurator (a utun's addresses route nothing), and never sent direct.
//
// Nothing outranks a more specific route, so foreign ones are shadowed:
// every on-link subnet that isn't trusted (TrustedOnLink: a public subnet
// a hostile network makes on-link, a private one the rules don't send
// direct) and every foreign route over tunneled destinations (a DHCP
// server's classless routes, another VPN's) gets more specific routes into
// the TUN covering what of it the rules don't send direct, but for the
// default gateways, which must stay reachable on-link. A foreign host
// route can't be outranked: Ahead counts those. Where another route holds
// the identity of one of ours (another VPN's own split routes, a reject
// route someone added), ours is split into more specific halves instead,
// so the layout never conflicts with what is there. Direct prefixes inside an
// on-link subnet, and link-local, multicast and loopback ones, are left to
// the OS's own routes.
func SplitRoutes(w Want, s netcfg.Survey) netcfg.Config {
	cfg, _, _ := splitRoutes(w, s)
	return cfg
}

// The ranges direct routes are never added for: the OS routes them on its
// own interfaces, and through a gateway they mean nothing.
var osScoped = []netip.Prefix{
	netip.MustParsePrefix("127.0.0.0/8"), netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("224.0.0.0/4"), netip.MustParsePrefix("255.255.255.255/32"),
	netip.MustParsePrefix("::1/128"), netip.MustParsePrefix("fe80::/10"), netip.MustParsePrefix("ff00::/8"),
}

func within(p netip.Prefix, among []netip.Prefix) bool {
	for _, q := range among {
		if q.Bits() <= p.Bits() && q.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// halves are p's two halves.
func halves(p netip.Prefix) [2]netip.Prefix {
	lo := netip.PrefixFrom(p.Addr(), p.Bits()+1)
	b := p.Addr().AsSlice()
	b[p.Bits()/8] |= 0x80 >> (p.Bits() % 8)
	hi, _ := netip.AddrFromSlice(b)
	return [2]netip.Prefix{lo, netip.PrefixFrom(hi, p.Bits()+1)}
}

func family(p netip.Prefix) netcfg.Family { return netcfg.FamilyOf(p.Addr()) }

func splitRoutes(w Want, s netcfg.Survey) (cfg netcfg.Config, ahead, overlayAhead int) {
	l := newSplitLayout(w, s)
	l.tunnelRoutes()
	l.directRoutes()
	l.upstreamRoutes()
	l.shadowForeign()
	slices.SortStableFunc(l.cfg.Routes, func(a, b netcfg.Route) int {
		if fa, fb := family(a.Dst), family(b.Dst); fa != fb {
			return int(fa) - int(fb)
		}
		return 0
	})
	return l.cfg, l.ahead, l.overlayAhead
}

// splitLayout is splitRoutes' work: what it lays out against, and the
// routes so far.
type splitLayout struct {
	w Want
	s netcfg.Survey
	// up: the TUN is up; overlay are its networks.
	up         bool
	overlay    []netip.Prefix
	overlaySet *lists.Set
	// thrown goes around the tunnel: the rules' direct set (never the
	// overlay, direct) and the endpoints.
	thrownSet *lists.Set
	thrown    []netip.Prefix
	direct    *lists.Set
	// trusted are the on-link subnets that keep their routes; gateways
	// the default routes by family, gatewayHosts those inside a trusted
	// subnet.
	trusted      []netip.Prefix
	gateways     map[netcfg.Family]netcfg.Route
	gatewayHosts []netip.Prefix
	// taken are the identities other routes hold, ours those of the
	// routes in cfg: ours must differ from theirs.
	taken, ours map[netip.Prefix]bool

	cfg                 netcfg.Config
	ahead, overlayAhead int
}

func newSplitLayout(w Want, s netcfg.Survey) *splitLayout {
	l := &splitLayout{w: w, s: s, up: TUNUp(w, s), overlay: prefixes(w.Overlay), ours: map[netip.Prefix]bool{}}
	var ob lists.Builder
	for _, p := range l.overlay {
		_ = ob.AddPrefix(p)
	}
	l.overlaySet, _ = ob.Build()
	var tb lists.Builder
	tb.AddSet(w.Direct.Minus(l.overlaySet))
	for _, a := range bypass(w.Bypass) {
		_ = tb.AddPrefix(netip.PrefixFrom(a, a.BitLen()))
	}
	l.thrownSet, _ = tb.Build()
	l.thrown = l.thrownSet.Prefixes()
	l.direct = w.Direct.Minus(l.overlaySet)
	for _, p := range s.OnLink {
		if p.Bits() > 0 && p.Bits() < p.Addr().BitLen() && TrustedOnLink(p, l.direct) && !overlaps(p, l.overlay) {
			l.trusted = append(l.trusted, p)
		}
	}
	l.findGateways()
	l.findTaken()
	return l
}

// findGateways notes the default routes. A default gateway stays reachable
// on-link only inside a trusted subnet: one a hostile network puts in the
// overlay's range or on a public "on-link" subnet would get that address
// in the clear. The links don't need it: they are bound to the physical
// interface and use its scoped routes; direct traffic via such a gateway
// enters the TUN instead (dropped, never leaked).
func (l *splitLayout) findGateways() {
	l.gateways = map[netcfg.Family]netcfg.Route{}
	for _, d := range l.s.Defaults {
		l.gateways[family(d.Dst)] = d
		if d.Gateway.IsValid() && within(netip.PrefixFrom(d.Gateway, d.Gateway.BitLen()), l.trusted) {
			l.gatewayHosts = append(l.gatewayHosts, netip.PrefixFrom(d.Gateway, d.Gateway.BitLen()))
		}
	}
}

// findTaken notes the identities other routes hold: on-link subnets,
// foreign routes, held ones, and the overlay configurator's routes into
// the TUN.
func (l *splitLayout) findTaken() {
	l.taken = map[netip.Prefix]bool{}
	for _, p := range l.s.OnLink {
		l.taken[p] = true
	}
	for _, r := range l.s.Routes {
		l.taken[r.Dst] = true
	}
	for _, p := range l.s.Held {
		l.taken[p] = true
	}
	for _, p := range l.overlay {
		for _, h := range netcfg.ConnectedRoutes(p) {
			l.taken[h] = true
		}
	}
}

func (l *splitLayout) add(r netcfg.Route) {
	if !l.ours[r.Dst] {
		l.ours[r.Dst] = true
		l.cfg.Routes = append(l.cfg.Routes, r)
	}
}

// free reports whether no route, ours or another's, holds p's identity.
func (l *splitLayout) free(p netip.Prefix) bool { return !l.taken[p] && !l.ours[p] }

func (l *splitLayout) carried(p netip.Prefix) bool { return l.up && (p.Addr().Is4() || l.w.IPv6) }

// tunnel routes p into the TUN, or rejects it while the TUN can't carry
// it.
func (l *splitLayout) tunnel(p netip.Prefix) netcfg.Route {
	if l.carried(p) {
		return netcfg.Route{Dst: p, Interface: l.w.TUN}
	}
	return reject(p)
}

func reject(p netip.Prefix) netcfg.Route { return netcfg.Route{Dst: p, Type: netcfg.RouteUnreachable} }

// hostAhead counts a foreign host route nothing can outrank: inside the
// overlay it hijacks a peer's address.
func (l *splitLayout) hostAhead(p netip.Prefix) {
	if overlaps(p, l.overlay) {
		l.overlayAhead++
	} else {
		l.ahead++
	}
}

// cover routes p as route says, or, where another route holds p's
// identity (another VPN's split routes, someone's reject route), its
// halves, and so on: ours are always more specific, so they win without
// touching the other's. Pieces that go direct are left to the direct
// routes; a host route that can't be outranked counts as ahead.
func (l *splitLayout) cover(p netip.Prefix, route func(netip.Prefix) netcfg.Route) {
	switch {
	case within(p, l.thrown):
	case l.free(p):
		l.add(route(p))
	case p.Bits() == p.Addr().BitLen():
		l.hostAhead(p)
	default:
		for _, h := range halves(p) {
			l.cover(h, route)
		}
	}
}

// tunnelRoutes are the split routes into the TUN, IPv6's reject routes
// behind them, and the overlay networks' reject routes.
func (l *splitLayout) tunnelRoutes() {
	all4, all6 := netip.PrefixFrom(netip.IPv4Unspecified(), 0), netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	for _, h := range halves(all4) {
		l.cover(h, l.tunnel)
	}
	h6 := halves(all6)
	if l.carried(all6) {
		for _, h := range h6 {
			for _, q := range halves(h) {
				l.cover(q, l.tunnel)
			}
		}
	}
	for _, h := range h6 {
		switch {
		case within(h, l.thrown):
		case l.free(h):
			l.add(reject(h))
		case !l.carried(all6):
			l.cover(h, reject)
			// Carried: the TUN's routes are more specific than whoever
			// holds h; only the reject behind them, for a crash, is
			// missing.
		}
	}
	// Each overlay network is rejected behind the overlay configurator's
	// halves into the TUN: when the TUN is gone (a crash takes its routes
	// along) overlay traffic, the DNS the OS was pointed at included, is
	// dropped instead of following the physical default route.
	for _, p := range l.overlay {
		if l.free(p) {
			l.add(reject(p))
		}
	}
}

// directRoutes send what goes around the tunnel via its family's default
// gateway; a default route's worth as its halves.
func (l *splitLayout) directRoutes() {
	for _, p := range l.thrown {
		ps := []netip.Prefix{p}
		if p.Bits() == 0 {
			h := halves(p)
			ps = h[:]
		}
		for _, p := range ps {
			gw, ok := l.gateways[family(p)]
			if !ok || l.taken[p] || within(p, osScoped) || insideOnLink(p, l.s.OnLink) {
				continue
			}
			l.add(netcfg.Route{Dst: p, Gateway: gw.Gateway, Interface: gw.Interface})
		}
	}
}

// upstreamRoutes are the direct DNS upstreams', for the resolver's
// sockets bound to the physical interface: a route scoped to it
// (RTF_IFSCOPE), via its gateway, which only sockets bound to it use, so
// nothing else goes around the tunnel to that address. Not for an
// upstream on-link (its subnet's route is on the interface already), on
// loopback or link-local, or in the overlay; for IPv6 only with an IPv6
// default route; not where another route holds that identity.
func (l *splitLayout) upstreamRoutes() {
	heldScoped := map[netcfg.Route]bool{}
	for _, r := range l.s.HeldScoped {
		heldScoped[netcfg.Route{Dst: r.Dst, Scope: r.Scope}] = true
	}
	for _, a := range upstreamAddrs(l.w.Upstreams) {
		p := netip.PrefixFrom(a, a.BitLen())
		gw, ok := l.gateways[family(p)]
		switch {
		case !ok || !gw.Gateway.IsValid() || gw.Interface == "":
		case within(p, osScoped) || overlaps(p, l.overlay) || insideOnLink(p, l.s.OnLink):
		case heldScoped[netcfg.Route{Dst: p, Scope: gw.Interface}]:
		default:
			l.cfg.Routes = append(l.cfg.Routes, netcfg.Route{Dst: p, Gateway: gw.Gateway, Interface: gw.Interface, Scope: gw.Interface})
		}
	}
}

// shadowForeign shadows every on-link subnet that isn't trusted and every
// foreign route.
func (l *splitLayout) shadowForeign() {
	for _, p := range l.s.OnLink {
		if p.Bits() == p.Addr().BitLen() || p.Bits() == 0 {
			continue // an address's own entry, a broadcast entry
		}
		if TrustedOnLink(p, l.direct) && !overlaps(p, l.overlay) {
			continue
		}
		l.shadow(p)
	}
	for _, r := range l.s.Routes {
		if r.Interface == l.w.TUN || r.Dst.Bits() == 0 || r.Type != netcfg.RouteUnicast {
			continue
		}
		l.shadow(r.Dst)
	}
}

// shadow routes into the TUN, more specifically than c, what of c the
// rules don't send direct, but for the default gateways and what the
// overlay configurator's halves outrank already.
func (l *splitLayout) shadow(c netip.Prefix) {
	exempt := slices.Clone(l.gatewayHosts)
	for _, p := range l.overlay {
		if c.Bits() <= p.Bits() {
			exempt = append(exempt, p)
		}
	}
	rest, ok := uncovered(c, l.thrownSet, exempt)
	if !ok {
		return
	}
	if c.Bits() == c.Addr().BitLen() {
		l.hostAhead(c) // nothing is more specific
		return
	}
	for _, q := range rest {
		l.place(c, q)
	}
}

// place routes q, a piece of c, into the TUN: a piece must be more
// specific than c, and no other route's identity, else it is split
// again.
func (l *splitLayout) place(c, q netip.Prefix) {
	switch {
	case q != c && l.free(q):
		l.add(l.tunnel(q))
	case q.Bits() == q.Addr().BitLen():
		l.hostAhead(q)
	default:
		for _, h := range halves(q) {
			l.place(c, h)
		}
	}
}

// insideOnLink reports whether p lies inside, and is smaller than, one of
// the on-link subnets: their routes reach it already.
func insideOnLink(p netip.Prefix, onLink []netip.Prefix) bool {
	for _, l := range onLink {
		if l.Bits() < p.Bits() && l.Contains(p.Addr()) {
			return true
		}
	}
	return false
}

// uncovered is what of c the tunnel must take back from a foreign route:
// c without what goes direct and what is exempt (trusted gateways, the
// overlay where its own routes win). False when nothing is left.
func uncovered(c netip.Prefix, thrown *lists.Set, exempt []netip.Prefix) ([]netip.Prefix, bool) {
	var b lists.Builder
	if b.AddPrefix(c) != nil {
		// A range lists can't hold (around IPv4-mapped IPv6): take it
		// whole, without exclusions.
		return []netip.Prefix{c}, true
	}
	var gb lists.Builder
	for _, g := range exempt {
		_ = gb.AddPrefix(g)
	}
	cs, _ := b.Build()
	gs, _ := gb.Build()
	rest := cs.Minus(thrown).Minus(gs)
	if rest.IsEmpty() {
		return nil, false
	}
	return rest.Prefixes(), true
}
