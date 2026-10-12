package routetable

import (
	"net/netip"
	"runtime"
	"slices"

	"github.com/KucherenkoIvan/thinkpol-vpn/internal/dataplane/netcfg"
	"github.com/KucherenkoIvan/thinkpol-vpn/internal/lists"
)

// Config is w as netcfg configuration for this OS's layout: policy
// routing on Linux (PolicyRouting), split routes in the main table on
// macOS (SplitRoutes).
func Config(w Want, s netcfg.Survey) netcfg.Config {
	if runtime.GOOS == "darwin" {
		cfg, _ := splitRoutes(w, s)
		return cfg
	}
	return PolicyRouting(w, s)
}

// Ahead counts what other software has in place that may route traffic
// around the tunnel and the layout can't override: on Linux, policy rules
// ahead of the tunnel's; on macOS, foreign host routes over tunneled
// destinations (see SplitRoutes).
func Ahead(w Want, s netcfg.Survey) int {
	if runtime.GOOS == "darwin" {
		_, n := splitRoutes(w, s)
		return n
	}
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
	cfg, _ := splitRoutes(w, s)
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

func splitRoutes(w Want, s netcfg.Survey) (netcfg.Config, int) {
	up := TUNUp(w, s)
	overlay := prefixes(w.Overlay)
	var ob lists.Builder
	for _, p := range overlay {
		_ = ob.AddPrefix(p)
	}
	overlaySet, _ := ob.Build()

	// What goes around the tunnel: the rules' direct set (never the
	// overlay) and the endpoints.
	var tb lists.Builder
	tb.AddSet(w.Direct.Minus(overlaySet))
	for _, a := range bypass(w.Bypass) {
		_ = tb.AddPrefix(netip.PrefixFrom(a, a.BitLen()))
	}
	thrownSet, _ := tb.Build()
	thrown := thrownSet.Prefixes()
	direct := w.Direct.Minus(overlaySet)

	gateways := map[netcfg.Family]netcfg.Route{}
	var gatewayHosts []netip.Prefix
	for _, d := range s.Defaults {
		gateways[family(d.Dst)] = d
		if d.Gateway.IsValid() {
			gatewayHosts = append(gatewayHosts, netip.PrefixFrom(d.Gateway, d.Gateway.BitLen()))
		}
	}

	// Identities other routes hold: ours must differ.
	taken := map[netip.Prefix]bool{}
	for _, p := range s.OnLink {
		taken[p] = true
	}
	for _, r := range s.Routes {
		taken[r.Dst] = true
	}
	for _, p := range s.Held {
		taken[p] = true
	}
	for _, p := range overlay {
		taken[p] = true // the overlay configurator's routes into the TUN
	}

	var cfg netcfg.Config
	ours := map[netip.Prefix]bool{}
	add := func(r netcfg.Route) {
		if !ours[r.Dst] {
			ours[r.Dst] = true
			cfg.Routes = append(cfg.Routes, r)
		}
	}
	carried := func(p netip.Prefix) bool { return up && (p.Addr().Is4() || w.IPv6) }
	tunnel := func(p netip.Prefix) netcfg.Route {
		if carried(p) {
			return netcfg.Route{Dst: p, Interface: w.TUN}
		}
		return netcfg.Route{Dst: p, Type: netcfg.RouteUnreachable}
	}

	ahead := 0
	// cover routes p as route says, or, where another route holds p's
	// identity (another VPN's split routes, someone's reject route), its
	// halves, and so on: ours are always more specific, so they win
	// without touching the other's. Pieces that go direct are left to the
	// direct routes; a host route that can't be outranked counts as
	// ahead.
	var cover func(p netip.Prefix, route func(netip.Prefix) netcfg.Route)
	cover = func(p netip.Prefix, route func(netip.Prefix) netcfg.Route) {
		switch {
		case within(p, thrown):
		case !taken[p] && !ours[p]:
			add(route(p))
		case p.Bits() == p.Addr().BitLen():
			ahead++
		default:
			for _, h := range halves(p) {
				cover(h, route)
			}
		}
	}
	reject := func(p netip.Prefix) netcfg.Route { return netcfg.Route{Dst: p, Type: netcfg.RouteUnreachable} }

	all4, all6 := netip.PrefixFrom(netip.IPv4Unspecified(), 0), netip.PrefixFrom(netip.IPv6Unspecified(), 0)
	for _, h := range halves(all4) {
		cover(h, tunnel)
	}
	h6 := halves(all6)
	if carried(all6) {
		for _, h := range h6 {
			for _, q := range halves(h) {
				cover(q, tunnel)
			}
		}
	}
	for _, h := range h6 {
		switch {
		case within(h, thrown):
		case !taken[h] && !ours[h]:
			add(reject(h))
		case !carried(all6):
			cover(h, reject)
			// Carried: the TUN's routes are more specific than whoever
			// holds h; only the reject behind them, for a crash, is
			// missing.
		}
	}

	for _, p := range thrown {
		ps := []netip.Prefix{p}
		if p.Bits() == 0 {
			h := halves(p)
			ps = h[:]
		}
		for _, p := range ps {
			gw, ok := gateways[family(p)]
			if !ok || taken[p] || within(p, osScoped) || insideOnLink(p, s.OnLink) {
				continue
			}
			add(netcfg.Route{Dst: p, Gateway: gw.Gateway, Interface: gw.Interface})
		}
	}

	shadow := func(c netip.Prefix) {
		rest, ok := uncovered(c, thrownSet, gatewayHosts)
		if !ok {
			return
		}
		if c.Bits() == c.Addr().BitLen() {
			ahead++ // a host route: nothing is more specific
			return
		}
		// A piece must be more specific than c, and no other route's
		// identity: else it is split again.
		var place func(q netip.Prefix)
		place = func(q netip.Prefix) {
			switch {
			case q != c && !taken[q] && !ours[q]:
				add(tunnel(q))
			case q.Bits() == q.Addr().BitLen():
				ahead++
			default:
				for _, h := range halves(q) {
					place(h)
				}
			}
		}
		for _, q := range rest {
			place(q)
		}
	}
	for _, p := range s.OnLink {
		if p.Bits() == p.Addr().BitLen() || p.Bits() == 0 {
			continue // an address's own entry, a broadcast entry
		}
		if TrustedOnLink(p, direct) && !overlaps(p, overlay) {
			continue
		}
		shadow(p)
	}
	for _, r := range s.Routes {
		if r.Interface == w.TUN || r.Dst.Bits() == 0 || r.Type != netcfg.RouteUnicast {
			continue
		}
		shadow(r.Dst)
	}
	slices.SortStableFunc(cfg.Routes, func(a, b netcfg.Route) int {
		if fa, fb := family(a.Dst), family(b.Dst); fa != fb {
			return int(fa) - int(fb)
		}
		return 0
	})
	return cfg, ahead
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
// c without what goes direct and the default gateways. False when nothing
// is left.
func uncovered(c netip.Prefix, thrown *lists.Set, gatewayHosts []netip.Prefix) ([]netip.Prefix, bool) {
	var b lists.Builder
	if b.AddPrefix(c) != nil {
		// A range lists can't hold (around IPv4-mapped IPv6): take it
		// whole, without exclusions.
		return []netip.Prefix{c}, true
	}
	var gb lists.Builder
	for _, g := range gatewayHosts {
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
