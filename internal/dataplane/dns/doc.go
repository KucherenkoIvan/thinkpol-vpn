// Package dns is the resolver on the node's overlay address, and what
// points the OS's resolver at it (docs/design/routing.md "DNS").
//
// DNS is routing: [Server] answers the space's overlay names itself,
// `<device>.<space>.internal` (`.internal` is reserved for private use,
// so a space's name can never shadow a real domain), sends the names the
// rules make `direct` to a domestic upstream, and every other name
// through the tunnel to a resolver at the exit. So no name leaves outside
// the tunnel unless the rules say it may, and GeoIP isn't fed a CDN's
// answers from the wrong country.
//
// # Who it answers
//
// The engine gives the server a new [Config] with every map and rule
// change ([Server.Update]):
//
//   - on a device, it listens on the device's overlay addresses and
//     answers the device itself only: [Config.Clients] are those
//     addresses, which the node's own processes ask from; a peer's address
//     never is one of them, whatever its WireGuard device allows it;
//   - on an exit (a server that allows egress), the same server is the
//     resolver at the exit: it listens on the exit's overlay addresses,
//     takes queries from the space's overlay networks only, and sends
//     every name to its own upstream ([Config.Route] nil: every name
//     direct);
//   - any other server runs none.
//
// A query from any other source is answered REFUSED; anything but one
// query (a response, another opcode, several questions) NOTIMP. An
// address it can't listen on yet (the TUN coming up) is retried every
// second, and said once in the log.
//
// # Names
//
// The overlay's names come from devices' sections of the map only (the
// space's name, the device's own and its peers'), so a device can name
// exactly the nodes it has as peers and a server holds no member names.
// The resolver serves the names of the peers WireGuard has now: a peer
// the map takes away leaves DNS with it. A name that isn't a valid label,
// or that two nodes claim, names neither; a space whose name isn't a
// valid label has no zone. Overlay answers are authoritative, with a TTL
// of 30 s.
//
// Some names are never forwarded:
//
//   - any name with an `internal` label anywhere, a search list's retry
//     of an overlay name (`peer.space.internal.lan`) included: one ending
//     in `internal` is answered from the zone, any other is NXDOMAIN;
//   - a reverse name under the overlay networks (or covering part of
//     them): an address's is answered (PTR) from the zone, a zone's is
//     NXDOMAIN;
//   - `resolver.arpa` (RFC 9462) is NXDOMAIN, so the OS never discovers
//     an encrypted resolver to upgrade to (DDR) that would bypass the
//     node.
//
// A name with escaped characters (`a\.b`) is refused: it would be matched
// by the rules as another name than the one asked.
//
// # Which way a name goes
//
// On a device, [Config.Route] is the device's effective rule list read by
// name (`rules.CompileNames`, in dataplane/rules): `domain` matches the
// name exactly, `domain-suffix` the name and every name below it,
// `default` every name; address matchers can't decide a name and are
// passed over. The fail-closed rules are the route table's: a matcher
// whose names aren't known (geosite, an unknown one) matches nothing and,
// unless it is `direct` itself, turns every later `direct` rule off; an
// unknown action or a chain that can't carry traffic blocks; a name no
// rule matches is blocked; with no rules at all every name is `direct`.
// A chain whose exit isn't a peer now blocks too.
//
// A [Route] is direct ([RouteDirect]), to a chain's exit ([RouteTunnel],
// at the exit's overlay addresses) or blocked ([RouteBlock]: SERVFAIL,
// asking no one). A name's rule picks only the upstream: the addresses in
// the answer are routed by the address rules like any other. A reverse
// name (PTR) of an address outside the overlay goes where its address's
// packets go ([Config.RouteAddr], the compiled rule table); a reverse
// zone that isn't one address is blocked, since no rule says where it
// goes.
//
// # Known leak: the CNAME
//
// A `direct` name whose answer is a CNAME into a tunnel-bound name is
// answered whole by the domestic upstream: the chain is resolved
// upstream, so the domestic upstream learns that the target was resolved.
// That is inherent in forwarding; the target's addresses are still routed
// by the rules. The alternative, resolving the chain's tunnel-bound tail
// again through the exit's resolver, was weighed: it hides the target but
// takes a second lookup per aliased name and splits one answer between
// two resolvers. The leak is accepted (RESIDUAL-RISKS.md RR1).
//
// # Upstreams
//
// `direct` names go to the domestic upstream, [Options.Upstreams] until
// [Server.SetUpstreams] replaces them (the OS's resolvers changed, or a
// worker's later config named others): on a device, `-dns-upstream`, else
// the resolvers the OS used before the node took over ([SystemUpstreams],
// read before the OS is pointed at the node, never the node's own
// addresses). While the OS's resolvers are followed, a change of them
// (see below) replaces the upstreams. In route-table mode the direct
// upstream's sockets carry the links' socket mark ([Options.Control]; on
// macOS they are bound to the physical interface instead), so they leave
// around the tunnel (TP-018, TP-019).
//
// Tunnel-bound names go to the resolver on the chain's exit's overlay
// address, at [Options.TunnelPort]. A device binds those sockets to the
// TUN ([BindToInterface]: SO_BINDTODEVICE on Linux, IP_BOUND_IF and
// IPV6_BOUND_IF on macOS; elsewhere they fail to open), and the overlay
// always routes into the TUN, so such a query leaves through the tunnel
// or not at all.
//
// Every exit (a server that allows egress) runs that resolver for the
// space's overlay, asking its own upstream: `-dns-upstream`, else the
// well-known public resolvers, Quad9 then Cloudflare over IPv4, then both
// over IPv6, port 53. When the uplink carries only one family, that
// family's go first, as of the last map applied: a later map's order and
// upstreams reach the running worker (SetUpstreams), an uplink change
// alone re-runs nothing. Not the host's own resolvers: on most clouds
// they sit on private or link-local addresses, which the worker's egress
// refuses, and widening it would open the provider's private network,
// metadata services included, to every space. An upstream the worker's
// egress refuses is not asked; on an exit it is named in health
// (`dns_upstream_refused`) and in the log, with a hint (`-dns-upstream`,
// or `-egress-allowed` where allowing it is worth it), while a server
// whose section allows no egress reports nothing: it is not an exit, and
// no device asks its resolver. With none left, tunnel-bound names fail.
//
// A query is forwarded with only the resolver's own EDNS record (a 1232
// byte buffer, the DNS flag day's, and the client's DO bit): none of the
// client's options (its subnet, cookies) travel upstream. Upstreams are
// tried in order, each with a timeout of two seconds; SERVFAIL or REFUSED
// from one moves on to the next, and when none answers the client gets
// SERVFAIL. Each try asks over UDP from a fresh socket connected to the
// upstream, with a random ID, and again over TCP when the answer is
// truncated or the socket gets a datagram that isn't the answer (another
// ID or question, garbage, too big): someone may be guessing at the query
// to answer it first. An attacker on the path to a direct upstream can
// still answer first; only DoT or DNSSEC validation would stop that. At
// most 256 queries are forwarded at once, 32 of one client; more are
// SERVFAIL.
//
// Answers are cached per route ([DefaultCacheSize] answers by default,
// least recently used first out): a direct upstream's answer is never
// served for a name that goes through the tunnel. Only NOERROR and
// NXDOMAIN answers that aren't truncated and pack into 4 KiB are kept,
// for their lowest TTL (at most an hour) or, negative, their SOA's (at
// most five minutes; 30 s without an SOA). The cache is flushed on every
// [Server.Update] (every map or rule change) and whenever the direct
// upstreams change.
//
// # Pointing the OS at it
//
// While a device is connected, the OS resolves through its resolver
// ([SetSystem]), and gets its own configuration back when the device
// disconnects or stops ([System.Restore]). [System.Update] points it at a
// new configuration over the current one: there is no moment the OS's own
// is back. [RestoreSystem], called when the node starts (after the host
// lock: one agent per host), puts back what a node that crashed or a
// machine that went down while connected left behind.
//
// While the node runs, the OS searches only the space's zone
// ([SystemConfig.Search]): a name that fails is never retried under the
// OS's own search domains, which the rules may send elsewhere, at the
// cost of short LAN names (`printer` for `printer.lan`) while connected.
//
// Unless `-dns-upstream` is set, the OS's own resolvers are followed:
// [SystemConfig.Upstreams] is told whenever another program changes them
// while the node runs, and they become the direct upstream. A failed
// read keeps the previous upstreams. A failed first read (before the OS
// is pointed, [SystemConfig.UpstreamsUnknown]) leaves none, and is
// [ErrUpstreamsStale] (`dns_upstreams_stale`) until a read works; that
// first good read is told whether or not it changed anything.
// `dns_upstreams_stale` is degraded, not `dns_not_protected`: the OS
// still resolves through the node, only `direct` names may not resolve.
//
// # Linux: systemd-resolved
//
// Whenever systemd-resolved runs (it owns its name on the system bus),
// the TUN becomes its link for every name, over D-Bus: the resolver's
// addresses, the routing domain `~.` plus the search domains, the default
// route, and nothing resolved would add on its own (LLMNR, mDNS, its own
// DNS-over-TLS or DNSSEC checks, which the node's resolver doesn't
// answer). Restore reverts the link (RevertLink; resolved also drops it
// when the TUN goes away).
//
// When /etc/resolv.conf sends everything to resolved's stub, resolved is
// the OS's resolver and its uplink servers
// (/run/systemd/resolve/resolv.conf) are the OS's own: they are read
// again every 5 s and become the domestic upstream when they change. A
// missing, unreadable or empty uplink file is a failed read: a stub host
// whose resolved never writes that file stays stale. An empty one is
// never an answer with no upstreams: resolved's writer writes its header
// comment even when it knows no servers, and replaces the file
// atomically (a temporary file renamed over it), so a zero-byte uplink
// is a file caught mid-write or truncated, and the rule assumes
// resolved's writer. An empty /etc/resolv.conf itself is still a good
// read (TP-117 owns that case).
//
// # Linux: /etc/resolv.conf
//
// Unless /etc/resolv.conf sends everything to resolved's stub and
// resolved runs, the file is rewritten too: the
// resolver's addresses, the search domains, the original's options, and
// the original itself in comment lines (as a symlink's target, when it
// was one), so it comes back at the node's next start even after a crash
// or a reboot, with nothing kept anywhere else. The rewrite is atomic (a
// new file, synced, renamed over it); only a file that can't be renamed
// over (a bind mount, as /etc/resolv.conf often is in containers: EBUSY,
// EXDEV) is rewritten in place. Restore puts the original back, as a
// file or the symlink it was; a resolv.conf another program wrote since
// is left alone.
//
// The file is watched (inotify on its directory, and polled every 2 s as
// a backstop) and taken back if another program rewrites it; what that
// program wrote becomes the new original, and the resolvers it names the
// domestic upstream. resolved's stubs (127.0.0.53, 127.0.0.54) are never
// used as a direct upstream: a file naming only them falls back to
// resolved's uplink file, and if that yields nothing the previous
// upstreams are kept (and the log says to set `-dns-upstream`). Behind
// the stub, a read of the OS's resolvers is a read of the uplink file;
// a missing uplink file, a dangling link or an empty file is a failed
// read.
//
// # macOS: configd's dynamic store
//
// The resolver configuration lives in configd's dynamic store, per
// network service: State:/Network/Service/<id>/DNS (what DHCP or a VPN
// published) and, where DNS servers were set by hand,
// Setup:/Network/Service/<id>/DNS, which wins over it. The store is
// driven through /usr/sbin/scutil's command language: pure Go, no
// SystemConfiguration framework (cgo).
//
// The resolver is published as a network service of the node's own
// (State:/Network/Service/<thinkpol's fixed id>/DNS): the resolver's
// addresses, an empty supplemental match domain and a search order ahead
// of the services' (100000, configd's default being 200000), which
// configd turns into an additional default resolver, unscoped, asked
// first. The service has no IPv4 or IPv6 entity on purpose: configd
// copies an entity's interface onto the service's resolver, and
// mDNSResponder sends to an interface's resolver bound to that interface
// (IP_BOUND_IF), which can't reach the overlay address, which only the
// utun routes: a resolver published on a physical interface's service
// gets no query at all. What the OS sends to the overlay address comes back out of
// the utun; the router writes it back in (router.Table.ReflectLocal).
//
// Failing closed, every active service's (one with an IPv4 or IPv6
// state) State: DNS key is overridden with the resolver and the search
// domains too, so the services' own resolvers (asked after the node's, or
// for questions scoped to an interface) lead nowhere else. The node's own
// service is published after the overrides and removed before they are
// put back, and every write is read back: a write the store took
// differently is no override. Setup: keys, configd's copy of the network
// preferences, republished from them whenever they change, are never
// written: a service with DNS set by hand keeps it as a fallback, which
// is `dns_not_protected`.
//
// The originals are kept in the store itself
// (State:/Network/thinkpol/DNS), which, like the overrides, lives until
// the machine restarts: a node that crashed puts them back at its next
// start ([RestoreSystem]), and a reboot has the system publish its own
// again. An original scutil can't set back as it was (nested values,
// values with spaces or quotes) is overridden all the same and put back
// by removing its key, so the system publishes its own again (State: at
// the next DHCP renewal or network change, Setup: when the network
// settings are saved again or at reboot): no DNS meanwhile, never a leak.
// A service that goes away or goes inactive gets its original back.
//
// The store is checked whenever configd notifies a change of the
// services' keys or the global IPv4 and IPv6 keys (a long-lived `scutil`
// running `n.watch`; a burst of notifications settles for 100 ms into one
// check), and every 30 s anyway; every 2 s while the store can't be
// watched. What the system published over an override (DHCP renewing, a
// new network, settings edited) is taken as the new original and
// overridden again, and the primary service's servers (set by hand, else
// published, the originals where overridden) become the domestic
// upstream. A failed read of them keeps the last ones (warned once) and
// makes the health say `dns_upstreams_stale`. No primary service
// (offline) empties them; with `-dns-upstream` they aren't read at all.
//
// Supplemental resolvers of other software (another VPN's per-domain DNS
// or its own default, /etc/resolver files) still take the names under
// their domains: that is `dns_not_protected`. iCloud Private Relay and
// encrypted-DNS profiles bypass the system resolver altogether, and
// nothing here sees them.
//
// # Elsewhere
//
// Windows and Android have no [SetSystem] yet: it fails, and
// [SystemUpstreams] is not known.
//
// # Protection is checked, never assumed
//
// [System.Problem] says why names may still be resolved outside the
// node's resolver ([ErrUnprotected]), and [Unprotected] reads it: any
// problem the OS adapter reports without naming it counts as unprotected,
// and only a problem whose every part is [ErrUpstreamsStale] doesn't. In
// systemd-resolved, a domain on another link or a global one (search or
// routing, where there are servers to send its names to) beats the TUN's
// `~.` for the names under it, and another `~.` shares every name;
// NetworkManager adds `~.` to the connection with the default route. The
// links are checked at setup and every 5 s. Any such domain, a rewrite of
// resolv.conf that fails, on macOS an override that doesn't hold, a
// service with DNS set by hand or another software's resolver, or a
// failure to point the OS at all (retried by the agent on its retry
// timer) makes the device's health say `dns_not_protected`, and
// `thinkpol connect` returns an error saying so while the tunnel stays
// up.
//
// # Nothing is logged about a query
//
// Names and answers never reach a log or the disk (docs/design/security.md "Node
// safety"): [Options.Log] gets failures to listen only, and
// [Server.Counters] are the only figures the resolver keeps.
package dns
