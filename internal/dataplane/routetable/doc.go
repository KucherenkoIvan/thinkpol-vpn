// Package routetable enforces routing rules in the OS routing table
// (docs/design/routing.md "Routing rules and DNS", route-table mode): everything enters
// the TUN except the rules' direct destinations and the links' endpoints,
// which leave through the physical default route. It matches by IP only
// (geoip, cidr); domain rules are skipped with a warning.
//
// [LayoutOf] lays a [Want] out as netcfg configuration, [Layout.Config]
// (on Linux, policy routing: a table of its own and rules per family,
// [PolicyRouting]; on macOS, split routes in the main table,
// [SplitRoutes]); an [Enforcer] applies it through a netcfg configurator
// of [netcfg.OwnerRouteTable] and keeps it in place as routing changes.
// [SocketControl] marks the transports' sockets (Linux) or binds them to
// the physical interface (macOS) so links bypass the tunnel whatever the
// table holds. A [Guard], the firewall's half, refuses on the physical
// interfaces what routing can't keep in the tunnel.
//
// # Small tables
//
// The direct destinations are a [lists.Set], which merges overlapping and
// adjacent ranges into the minimal list of prefixes: a country list is
// thousands of prefixes, and every one is a route (a throw on Linux, a
// gateway route on macOS). Windows, which has no adapter yet (TP-047), is
// known to be slow with big tables.
//
// # Linux: policy routing
//
// [PolicyRouting] lays the table out per family, in four rules and a
// table of its own ([Table], 0x7470):
//
//   - Rule 5298 ([PriorityLinks]) looks up the main table, without its
//     default routes, for lookups bound to an interface (oif): one rule
//     per link but the TUN and loopback, kept up to date as links come and
//     go. That is how the kernel resolves the gateway of a route added
//     with its device (a DHCP client's default route, also one inside the
//     overlay's range or on a subnet the other rules don't know yet), so
//     gateways always resolve on the physical side.
//   - Rule 5299 ([PriorityOverlay]) looks the overlay's networks up in
//     [Table]: the overlay's routes into the TUN, an unreachable route
//     behind each, so nothing in main (a DHCP server's classless route
//     into the overlay's range, an address inside it, an advertised prefix
//     inside its /48) gets overlay traffic.
//   - Rule 5300 ([PriorityMain]) looks up main, without its defaults, for
//     the on-link subnets of the physical interfaces that lie entirely
//     inside the local ranges (RFC 1918, link-local, ULA: [lists.Local])
//     and inside what the rules send direct, and don't overlap the
//     overlay ([TrustedOnLink]; the kernel's routes for the interfaces'
//     addresses, mirrored as `to <prefix>` rules). A network can't widen
//     what goes direct, and where the rules tunnel or block a private
//     range, being on-link doesn't override them.
//   - Rule 5301 ([PriorityTunnel]) sends every packet without the links'
//     firewall mark ([Mark], 0x7470) to [Table]: a default route into the
//     TUN, an unreachable IPv6 default behind it, and a throw route per
//     direct prefix and per link endpoint.
//
// Thrown and marked packets go on to the main table and its physical
// default route, so nothing names the gateway: DHCP and roaming need no
// change. No other route in main, such as a DHCP server's classless routes
// (TunnelVision, CVE-2024-3661), another VPN's split defaults or a router
// advertisement's routes, comes before the tunnel, and no public subnet a
// network makes "on-link" (a DHCP address 203.0.113.50/24, a PPP peer, an
// advertised prefix: TunnelCrack's LocalNet) is reached outside it. The
// cost: hosts on a public on-link LAN, and a gateway route added without
// its device, go through the tunnel unless the rules send them direct (a
// setting could opt a LAN in later).
//
// Whatever the TUN can't take meets an unreachable route (metric 2048,
// behind the TUN's routes): IPv6 when the overlay doesn't carry it, the
// overlay and both families while the TUN is down or gone. IPv4's
// unreachable default is put in only then (by the re-apply after the link
// event, a debounce later), because a reject route would also answer the
// kernel's gateway lookups for an interface the rules don't know yet;
// the TUN's own default, bound to the TUN, lets them through to main. All
// of IPv4 direct, which the overlay's network never allows, is a throw
// default instead.
//
// Sockets bound to an interface (SO_BINDTODEVICE, IP_UNICAST_IF, an
// IP_PKTINFO ifindex: `ping -I`, NetworkManager's connectivity checks,
// systemd-resolved's per-link DNS) can't be kept in the tunnel by
// routing: the kernel routes them out of their interface, by main's
// default route if nothing else matches. Confining them is the
// firewall's: for IPv6 the [Guard] below; IPv4's bound sockets leave by
// main's default route until the kill switch (TP-048), a separate owner
// with its own table. Forwarded traffic is never bound to an interface,
// and rule 5301 keeps it in the tunnel.
//
// [Layout.Ahead] counts other software's policy rules ahead of rule 5301
// ([Status.RulesAhead]; health `policy_rules_ahead`): they may route
// around the tunnel.
//
// # The links' sockets
//
// The transports' sockets carry the mark on Linux ([SocketControl]:
// SO_MARK, which needs CAP_NET_ADMIN, set by the transport adapter through
// its socket Control, never by WireGuard, which has no sockets); a socket
// that can't be marked fails to open rather than loop through the tunnel.
// The direct DNS upstream's sockets carry it too. The endpoints' throws
// keep links out of the tunnel even without the mark, and keep strict
// reverse-path filtering happy. A throw covers an endpoint's whole
// address, so any traffic to an entry's address goes around the tunnel;
// for an endpoint behind a CDN, whose address serves many sites, the
// throw should narrow to the transport's flow (protocol and port rules)
// when such transports come.
//
// On macOS [SocketControl] binds the links' and the direct DNS upstream's
// sockets to the interface of their family's default route
// (IP_BOUND_IF/IPV6_BOUND_IF through package ifbind), looked up as each
// socket opens, so a link redialed after the network changed follows it.
// A socket with no default route for its family fails to open. Bound
// sockets never route into the utun, but reach only destinations whose
// own route is on that interface (an on-link subnet, the layout's
// endpoint and direct routes): the primary interface has no scoped
// default route, and the kernel answers EHOSTUNREACH for the rest. That
// is why the direct DNS upstreams get scoped routes (below).
//
// # macOS: split routes
//
// macOS has no policy routing, so [SplitRoutes] puts everything in the
// main table, where routes compete by prefix length alone and the OS's
// default routes stay as they are:
//
//   - IPv4: 0.0.0.0/1 and 128.0.0.0/1 into the utun (reject routes while
//     it is down).
//   - IPv6: ::/2, 4000::/2, 8000::/2 and c000::/2 into the utun while it
//     is up and carries IPv6, with reject routes ::/1 and 8000::/1 always
//     behind them, so IPv6 is blocked but for direct destinations whenever
//     the utun can't take it, after a crash too (a utun dies with its
//     process, taking its routes along; IPv4 then follows the physical
//     default route, as on Linux).
//   - Direct prefixes and link endpoints go via the family's default
//     gateway ([netcfg.Survey.Defaults]), but for those inside an on-link
//     subnet and the OS's own link-local, multicast, broadcast and
//     loopback ranges, which its interface routes reach. None is added for
//     a family without a default route, nor where another route already
//     holds the prefix (that route keeps it). These routes name the
//     gateway, so a network change (Wi-Fi, sleep and wake) re-applies
//     them from the routing socket's events; netcfg changes what moved in
//     place, or deletes and adds it where the kernel refuses, and direct
//     traffic meanwhile enters the utun: dropped, never leaked.
//   - The overlay's networks are routed into the utun by the overlay's
//     own configurator as their two halves (a utun is point-to-point: its
//     addresses route nothing; [netcfg.ConnectedRoutes]), with a reject
//     route for each whole network behind them that outlives the utun:
//     after a crash overlay traffic, and the DNS the OS was pointed at,
//     is dropped rather than sent out the physical interface. The overlay
//     is never direct, so its ULA /48 is carved out of a direct fc00::/7.
//
// Since nothing outranks a more specific route, foreign ones are
// shadowed: every on-link subnet that isn't trusted (the same rule as on
// Linux, [TrustedOnLink]) and every foreign route over tunneled
// destinations (a DHCP server's classless routes, TunnelVision; a router
// advertisement's prefix or a public "on-link" subnet, LocalNet; another
// VPN's routes; one into the overlay's range) gets more specific routes
// into the utun covering what of it isn't direct. A default gateway stays
// reachable on-link only inside a trusted subnet: one a hostile network
// puts in the overlay's range or on a public subnet gets nothing in the
// clear. The links don't need it, being bound to the physical interface,
// and direct traffic via it enters the utun, dropped.
//
// A foreign host route can't be outranked. Over a tunneled destination it
// is counted ([Layout.Ahead], [Status.RulesAhead], health
// `policy_rules_ahead`); over an overlay address it takes a peer's traffic
// out of the tunnel in the clear ([Layout.OverlayAhead],
// [Status.OverlayAhead], health `overlay_routes_ahead`, down). Unlike
// Linux, where unknown routes never come before the tunnel, a new on-link
// subnet or classless route wins on macOS until the watcher re-applies (a
// debounce after the routing socket's event). Blocking a foreign host
// route is the firewall's, as are interface-bound sockets and sockets
// routed by their source address: for IPv6 the leak guard's pf anchor
// refuses all of them on the physical interfaces (package firewall; not
// yet proven on a device: TP-096); IPv4 waits for the kill switch
// (TP-048).
//
// No route of ours takes an identity another route holds
// ([netcfg.Survey.Held]): where another VPN has its own split routes, or
// anyone a route at one of our destinations, ours go more specific
// instead (halves, and their halves), so applying never conflicts with
// what is there. That holds for the routes of a corrupt route record
// too, which netcfg sets aside and counts as foreign
// ([netcfg.Survey.SetAside]): a crashed run's reject and direct routes
// stay in place until reboot, never removed on a guess. The enforcer
// counts this boot's set-aside records ([Status.RecordsSetAside]; health
// `route_record_set_aside`, degraded) and warns of each once, naming the
// file.
//
// # Direct DNS upstreams
//
// On macOS each direct DNS upstream ([Want.Upstreams]) that isn't on-link
// gets a host route via the gateway scoped to the default route's
// interface (RTF_IFSCOPE, route(8)'s -ifscope): only sockets bound there
// use it, so it takes nobody else's traffic around the tunnel. None is
// added for an upstream on loopback, link-local or multicast, inside the
// overlay, without a default route of its family (IPv6 upstreams only
// with an IPv6 default route), or where a foreign scoped route holds that
// identity ([netcfg.Survey.HeldScoped]). It follows the gateway like the
// direct routes. In netcfg, and in its record, a route's identity is its
// destination and, if scoped, its interface.
//
// The same upstreams, with their ports, are what the leak guard exempts
// for DNS ([Exempt.Upstreams], [GuardFor]), for a guard on an OS without
// socket marks (TP-078): one source for both. The engine never sees them:
// the agent's adapter of the engine's route-table port adds them to the
// Want, from the resolver's upstreams and the system's when they change.
// Linux needs no routes for them: their sockets carry the mark.
//
// # Keeping the table in place
//
// The data-plane engine hands the [Enforcer] (through the agent's
// adapter) a new Want whenever the rules change: a map, the device's
// choice, a list arriving. Direct prefixes the new rules drop leave the
// table before the router's table changes, new ones come after; a removal
// that fails falls back to nothing direct (everything into the TUN, where
// the router drops what it calls direct).
//
// An Apply is all or nothing: when [Enforcer.Enforce] fails, what was in
// place stays. Between Wants the Enforcer keeps the last one in place on
// its own goroutine, from [netcfg.Configurator.Watch]: it re-applies,
// a debounce (200 ms) after a burst of events, when a link comes, goes or
// changes state (a TUN going down takes its IPv4 route along without
// telling anyone), when an interface's on-link routes or a default route
// change, when its own routes or rules are removed (on macOS, when any
// foreign route comes, goes or changes), once after each change of its
// own, every [Backstop] (a minute) anyway, and every [RetryAfter] (5 s)
// while that fails. A re-apply that finds everything in place changes
// nothing. [Status] says when the table isn't enforced (the TUN down
// included: [ErrorTUNDown]) and the agent's health then says
// `route_table_not_enforced` (down).
//
// # The leak guard
//
// For IPv6 the route table carries a leak guard (TP-021), the [Guard]
// port: the agent fills it with package firewall's adapter (nftables on
// Linux, a pf anchor on macOS; routetable never imports firewall), and
// [GuardFor] says what it exempts: exactly what the table throws (the
// direct destinations and the endpoints), the links' marked sockets, the
// direct DNS upstreams, and link-scoped IPv6 ([LinkScoped]). What the
// guard refuses and how is package firewall's.
//
// The Enforcer applies the guard after the routes on every Apply and
// re-apply; applying what is in place again checks it is still whole,
// and the adapter rebuilds it if anything differs. While a re-apply of
// the routes fails, the guard stays the one for the routes in place (the
// last Want that went in): an Apply is all or nothing, so the previous
// routes stay, and so must their guard. When the guard's own Watch says
// it may have changed from outside, the Enforcer puts it back alone, a
// debounce later.
//
// The guard has a status of its own ([Status.GuardEnforced],
// [Status.GuardError]): its failure never fails the routes or an Enforce.
// A failing guard says [ErrorGuard] (health `ipv6_guard_not_enforced`) and
// is retried every [RetryAfter], logged at most once a minute with the
// count of failures since. An error wrapping [ErrGuardUnsupported] is
// terminal: the Enforcer stops applying and watching the guard and says
// [ErrorGuardUnsupported] (health `ipv6_guard_unsupported`), so the CLI
// and the tray can say that IPv6 from interface-bound apps isn't
// confined. A device still connects: not failing closed where the OS
// can't hold the guard is a decision.
//
// [Enforcer.Close] removes the guard before the routes, while the
// route table's owner lock is held; the configurator's Close lets go of
// the lock even when it fails, so a second Close removes nothing (the
// next run's live guard may be in its place by then). [Clear], for a
// start without connecting, removes a crashed run's guard too, with a
// fresh Guard, and only while it holds the owner lock.
//
// # Ownership and crashes
//
// Everything the table holds carries the owner's identity: on Linux route
// protocol 86 on the routes and the rules (rules need Linux 4.17 to keep
// a protocol: netcfg checks the rules it added came back with it, and on
// an older kernel deletes them and fails with errors.ErrUnsupported, which
// the Enforcer takes as final, [ErrorUnsupported], rather than leave rules
// it can't tell from others); on macOS RTF_PROTO2 and the owner's record
// (package netcfg). So a restart after a crash takes the table over, a
// stop removes it, and a device that starts without connecting, or fails
// to start, removes what a crash left ([Clear]; the agent clears the route
// table first, its leak guard with it, then the overlay's routes).
//
// After a crash IPv6 stays unreachable but for direct destinations until
// the agent starts again, bound sockets included (the guard stays too);
// IPv4 flows, as with the kill switch off. That is the M1 behaviour; the
// decided posture is stricter (docs/design/security.md "Kill switch").
package routetable
