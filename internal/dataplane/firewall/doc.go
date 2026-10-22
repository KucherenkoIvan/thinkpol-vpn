// Package firewall keeps traffic from leaving around the tunnel where
// routing can't: the IPv6 leak guard, an adapter for routetable's Guard
// port that the agent composes with the route table (TP-021: nftables on
// Linux; TP-078: a pf anchor on macOS) and, later, the kill
// switch (TP-048: pf, nftables, WFP). Desktop-only: it imports routetable,
// never the other way round.
//
// # The leak guard
//
// Routing keeps a device's traffic in the tunnel, but not a socket bound
// to an interface (SO_BINDTODEVICE, IPV6_UNICAST_IF, an IPV6_PKTINFO
// ifindex: `ping -I`, NetworkManager's connectivity checks,
// systemd-resolved's per-link DNS): the kernel routes it out of its
// interface whatever the table says. [IPv6Guard] is the firewall half of
// enforcement for IPv6, the [routetable.Guard] the agent hands the route
// table's [routetable.Enforcer]. It refuses IPv6 a process of the device
// sends out of any interface but the TUN and loopback, except what
// [routetable.Exempt] lets out, which [routetable.GuardFor] derives from
// the same Want as the routes: the direct destinations and the links'
// endpoints (exactly what the route table throws, endpoints as whole
// addresses), link-local unicast and multicast ([routetable.LinkScoped]),
// the links' marked sockets ([routetable.Mark]) and the direct DNS
// upstreams. So whether IPv6 goes into the TUN (an exit with NAT66), meets
// an unreachable route (an overlay without IPv6) or is refused by an exit
// without IPv6, the device's own IPv6 leaves a physical interface only to
// direct destinations and entries, on the link, or from the links' own
// sockets.
//
// Only IPv6 is the guard's: IPv4's interface-bound sockets still leave by
// the main table's default route until the kill switch (TP-048), a
// separate owner with its own table or anchor. The guard is the
// connection's, in place while a device is connected, not the kill
// switch (DESIGN.md "Kill switch"). Forwarded traffic isn't its business:
// nothing forwarded is bound to an interface, and routing (rule 5301 on
// Linux) keeps it in the tunnel.
//
// When the guard goes in, how it is kept for routes whose re-apply fails,
// and when it is removed (under the route table's owner lock, also by
// [routetable.Clear] after a crash) is the [routetable.Enforcer]'s.
//
// The guard has a status of its own, apart from the routes': its failure
// never fails the routes or a connect. An ordinary failure is retried
// every [routetable.RetryAfter] and the health says
// `ipv6_guard_not_enforced`. An OS that can't hold the guard at all
// (Apply's error wraps [routetable.ErrGuardUnsupported]) stops it for good
// for that Enforcer, and the health warns `ipv6_guard_unsupported`, so
// the CLI and the tray can say that IPv6 from interface-bound apps isn't
// confined. That is a decision: such a device still connects rather than
// failing closed.
//
// # Linux: an nftables table
//
// On Linux (desktop only: `linux && !android`) the guard is an nftables
// table of its own, `inet thinkpol-guard` ([GuardTable]), owned by its
// name the way the route table's routes are owned by their protocol, so a
// successor finds what a crashed run left. [NewIPv6Guard] guards the
// calling thread's network namespace, [NewIPv6GuardInNamespace] another
// one without entering it. The table is:
//
//	table inet thinkpol-guard {
//	  set exempt6 { type ipv6_addr; flags interval; elements = <Exempt.Ranges6> }
//	  chain output { type filter hook output priority 2147483647; policy accept;
//	    oifname "lo" accept
//	    oifname <TUN> accept
//	    meta nfproto != ipv6 accept
//	    meta mark <Mark> accept
//	    ip6 daddr @exempt6 accept
//	    icmpv6 type 133-137 ip6 hoplimit 255 accept          (neighbour discovery)
//	    icmpv6 type { 130-132, 143 } ip6 hoplimit 1 accept   (MLD)
//	    meta l4proto tcp counter reject with tcp reset
//	    counter reject with icmpx admin-prohibited
//	  }
//	}
//
// The output chain is hooked after every other output chain
// (NF_IP6_PRI_LAST): a chain that re-marks or reroutes a packet does so
// before the guard sees it, never after. A packet passes when it leaves
// through loopback or the TUN, carries the links' mark (the transports'
// sockets, set by the transport adapter, and the direct DNS upstream's
// sockets: Exempt.Upstreams are left to the mark here), goes to the
// interval set `exempt6` (the direct destinations, the endpoints and the
// link-scoped ranges: exactly the throws, plus the link), or stays on the
// link: neighbour discovery (ICMPv6 133 to 137) only with hop limit 255
// and MLD (130 to 132, 143) only with hop limit 1, whatever their
// destination (a neighbour solicitation to a global address), so a raw
// socket's ND or MLD can't leave the link. Everything else is refused,
// not dropped: TCP gets a reset and the rest an ICMPv6 "administratively
// prohibited", so an app learns at once and falls back to IPv4 or the
// tunnel.
//
// [IPv6Guard.Apply] replaces the whole table in one transaction (add,
// delete, add the table, then the set, its elements and the chain), so
// there is never a moment without a guard, whether or not the table, or
// a crashed run's, was there. A country-sized set (some ten thousand
// prefixes) is one transaction of tens of milliseconds: its elements go
// in messages of 1024 (one netlink attribute stays under its 64 KiB
// limit), over sockets whose buffers are forced to 8 MiB. Applying what
// is in place again compares the table with what it wants (the chain as
// hooked, every rule's expressions in order, counters aside, and every
// set element, in any order: an element added is a leak, one removed a
// refusal) and rebuilds it if anything differs. The table stays when the
// process dies, so a crash leaves IPv6 confined as the route table's
// unreachable default does; [IPv6Guard.Close] removes it, and a fresh
// guard's Close removes a crashed run's.
//
// [IPv6Guard.Watch] subscribes to nftables' events and signals, coalesced,
// whenever something of the guard's table changes from outside: a
// deletion (a table, chain, rule or set: `nft flush ruleset`, a firewall
// service's reload), a rule added or replaced, a set element added or
// removed. When the socket overflows (events may have been lost) it
// signals at once and again a second later. The Enforcer then re-applies
// the guard, so it is right again within about a second. The guard's own
// Apply shows up too, and finds the table whole.
//
// What the comparison and the watch don't catch today (TP-126, and
// RESIDUAL-RISKS.md RR11): the table's flags, so a table made dormant
// (`flags dormant`) keeps its rules but no longer filters, and is never
// repaired; chains other than its own, so a base chain someone adds to the
// guard's table, which can set the links' mark before the guard's chain
// sees the packet, is never repaired; and, for the watch only, a change of
// the output chain's policy: the comparison catches it, but the guard is
// re-applied only with the next routing event, at the latest by the route
// table's one-minute backstop.
//
// The guard's first request is a dump of the inet tables. Its answer, and
// only its answer, can make the guard unsupported: an error meaning no
// nf_tables in the kernel (EPROTONOSUPPORT, EAFNOSUPPORT, EOPNOTSUPP,
// EINVAL) wraps [routetable.ErrGuardUnsupported]. Any other error, and
// any error of a later request (an EOPNOTSUPP ack to a batch included),
// is an ordinary failure, retried; until the dump succeeds once, each
// request asks again. On such a kernel Close has nothing to remove.
//
// # macOS: a pf anchor
//
// On macOS the guard is a pf anchor, `com.apple/000.thinkpol`
// ([GuardAnchor]), under the hook Apple's main ruleset has for its own
// anchors (`anchor "com.apple/*"`, from /etc/pf.conf, which the system
// loads at boot without enabling pf); /etc/pf.conf is never edited. pf
// evaluates the anchors under com.apple in name order, so the `000.` puts
// ours before Apple's own (200.AirDrop, 250.ApplicationFirewall): no
// quick pass of theirs runs first. Every pfctl run is /sbin/pfctl by its
// absolute path, in the C locale, bounded at 15 s; with no pfctl at all
// the guard is unsupported.
//
// An anchor nothing evaluates guards nothing, so every apply and every
// check reads the main ruleset (`pfctl -s rules`) first. Without a line
// `anchor "com.apple/*"`, alone or with `all` (a narrowed one, `in`, `on
// en0`, `inet`, doesn't count), the guard is unsupported
// (`ipv6_guard_unsupported`, terminal for the connection, as a kernel
// without nf_tables is on Linux). With a `pass ... quick` above the hook
// that an outgoing IPv6 packet could match (not `in` only, not `inet`
// only) the guard isn't enforced (`ipv6_guard_not_enforced`, retried),
// since evaluation ends there.
//
// The anchor's rules are IPv6 only (IPv4's decisions stay whoever
// else's), outgoing only and stateless: pf keeps at most 10000 states by
// default, and a pass with state on the utun would put every tunnelled
// connection there. In order:
//
//	pass out quick on lo0 inet6 all no state
//	pass out quick on <utun> inet6 all no state
//	pass out quick inet6 from any to <thinkpol_exempt6> no state
//	pass out quick inet6 proto { tcp, udp } from any to <upstream> port <its port> no state   (each upstream)
//	pass out quick inet6 proto ipv6-icmp from any to <upstream> icmp6-type { 135, 136 } no state   (each upstream address)
//	pass out quick inet6 proto ipv6-icmp from any to ff00::/8 icmp6-type { 130, 131, 132, 143 } no state
//	block return out quick inet6 all
//
// What each rule is for:
//
//   - The table `thinkpol_exempt6` holds Exempt.Direct's IPv6 (the direct
//     destinations and the entries, as whole addresses like Linux's
//     throws) and link-local unicast and multicast, merged into the
//     fewest prefixes. The link-scoped ranges are all neighbour discovery
//     needs: a neighbour solicitation to a global address leaves only if
//     that address is exempt.
//   - DNS, TCP and UDP, passes to each IPv6 direct DNS upstream on its own
//     port, one rule pair per upstream (Exempt.Upstreams, which carry
//     their ports). macOS has no socket mark, so the upstreams' sockets
//     are bound to the physical interface instead (ifbind), and only DNS
//     to them is exempt, not every socket's traffic to that address. The
//     resolver asks plain DNS, no DoT. A link-local upstream is in the
//     exempt table already, and pf couldn't name it without its
//     interface.
//   - Neighbour solicitations and advertisements (135, 136) pass to each
//     upstream's address: only an on-link upstream needs them, for its
//     unicast neighbour probes; for one off the link they are two ICMPv6
//     types a router could forward, nothing more.
//   - MLD (ICMPv6 130 to 132, 143) passes to multicast (ff00::/8), any
//     scope.
//   - `block return` refuses the rest: TCP gets a reset, the rest an
//     ICMPv6 unreachable, so apps fail at once.
//
// pf can't match a hop limit. Linux passes neighbour discovery only with
// 255 and MLD only with 1, so there a raw socket's ND or MLD can't leave
// the link; here MLD-typed ICMPv6 can go to any multicast group, with
// whatever hop limit its sender (root) gives it, and the multicast
// destination is all that keeps it on the link.
//
// # macOS: loading and checking
//
// The table goes in with the rules in one `pfctl -a com.apple/000.thinkpol
// -f - -o none`: one pf transaction, so the rules and the table they look
// up change together, and a failed load leaves what was there, a guard at
// least as strict as either. The rule optimizer is off: pf.conf(5)'s
// default, `basic`, re-orders rules (and may merge them into a table),
// and the guard checks the listing it reads back in the order and shape
// it wrote, so a re-ordered listing would fail every load. A table
// defined with a list gets exactly that list on every load. It isn't
// `const`: that would stop `pfctl -T add`, but OpenBSD's pf refuses to
// change a const table in place, and a reload that can't narrow the table
// would leave a wide preset's exemptions behind; the guard's poll undoes a
// `-T add` instead.
//
// After a load the guard reads the anchor back: its rules, which pfctl
// lists its own way (protocol and ICMPv6 type names, implied options, a
// list expanded into one rule per item), each checked for the words it
// must hold and every pass for `no state`; and every entry of the table,
// which must be exactly what it loaded. It keeps that listing, and every
// later check compares the anchor with it exactly, line for line and
// entry for entry.
//
// A load pfctl takes but whose read-back the guard refuses (a listing out
// of order or shape, a table unlike the one loaded) stays in place, not
// flushed, and the apply fails and is retried. pf enforces it whenever pf
// is on, on the guard's reference after an earlier good load or on
// another enabler's (the Application Firewall's); the guard never takes a
// reference for it. Flushing would leave an empty anchor, which passes
// all IPv6. The guard's rules are all `quick` and end in the block, so a
// re-ordered listing is never wider than the rules written. A listing
// with other rules than those written (a pass that lost a word, a pass
// with state) or a table wider than the one loaded takes more than the
// written load: someone changing the anchor between the load and the
// read-back, or a pfctl that optimized it anyway (`basic` may merge rules
// into a table); either is enforced as it is until a retry reads the
// anchor back whole. Reloading the last verified guard instead was
// rejected: it guards the previous Exempt, so after a preset moves an
// address from direct to tunnelled it would exempt that address around
// the tunnel; and its own read-back can be refused the same way.
//
// pf passes a packet that matches a state without evaluating any rule
// (its state policy is floating). So after a load, after enabling pf, and
// after any apply that follows a failed one (a quick pass above the hook
// keeps state by default, and its states outlive it) the guard lists the
// states (`pfctl -s states`) and kills the IPv6 ones whose other end
// isn't in the exempt table, each by its two ends, `pfctl -k <host's end>
// -k <other end>` and the reverse; states to exempt destinations and IPv4
// ones are left alone. An upstream's address isn't exempt for this: `-k`
// names hosts, not ports, so its states go too, and DNS goes on through
// its stateless rule. Killing a tunnelled connection's state is harmless
// the same way: the anchor passes it statelessly. States made between two
// polls while something bypassed the guard are killed at its next
// successful apply, not at once.
//
// # macOS: enabling pf by reference
//
// pf is enabled by reference: `pfctl -E` takes one and prints its token,
// which goes at once to a record, /private/var/db/thinkpol/pf-guard.token
// in [netcfg.StateDir], with the boot session and the pid of that pfctl.
// So the guard neither turns off a pf someone else enabled (the
// Application Firewall holds a reference of its own when it is on) nor
// leaves pf on when it goes. pf is enabled after the anchor is loaded, so
// it comes on with the guard in place.
//
// A token `pfctl -E` doesn't print readably is looked up in `pfctl -s
// References` by that pid; until it is found it is recorded by pid alone,
// and the apply and the close both fail, so a reference is never held
// unrecorded or forgotten. A reference is released (`pfctl -X`) only while
// `pfctl -s References` lists that token as taken by that pid: a token is
// a kernel address's hash and a pid is reused in time, so a released
// value can come back as someone else's; both matching is as close as pf
// lets anyone tell. If the guard finds pf off (someone ran `pfctl -d`), it
// takes a new reference first, then releases the old one if pf still
// lists it.
//
// # macOS: polling
//
// pf has no event stream, so [IPv6Guard.Watch] polls every 10 s: the hook,
// the anchor's rules and table, and pf enabled (four pfctl runs, each
// bounded at 15 s), and whether its last apply failed, so a retry is due.
// The Enforcer then puts back what changed: `pfctl -d`, a flush, an entry
// added, a replaced main ruleset that still has the hook are undone within
// about 10 s, not a second as on Linux. Suspected but not proven to be
// missed (TP-126): `set skip on <interface>`, and a `pass quick` in
// another com.apple anchor evaluated before the guard's. A main ruleset
// replaced without the hook makes the guard unsupported.
//
// # macOS: crashes and reboots
//
// The anchor and the reference stay when the agent dies, so a crash
// leaves IPv6 confined, as the route table's reject routes do (fail
// closed). The next start's [routetable.Clear], under the route table's
// owner lock, closes a fresh guard, which flushes the anchor's rules and
// table (`-F rules`, `-F Tables`: `-F all` would also flush pf's global
// state table and statistics; an anchor that doesn't exist counts as
// empty, whatever pfctl answers for it) and releases the recorded
// reference. A guard that applies instead takes that reference over. The
// anchor goes before the reference, so pf is never left off with the
// anchor still meant to be in place. A reboot takes both, and the record,
// stamped with an earlier boot, is dropped without releasing anything.
// [IPv6Guard.Apply] and [IPv6Guard.Close] change pf, and only the
// Enforcer calls them, holding its owner lock; Watch only reads.
//
// # What the macOS guard doesn't do
//
//   - Match MLD's hop limit (above).
//   - See a quick pass inside an anchor the main ruleset evaluates before
//     the hook.
//   - Confine IPv4: that is the kill switch's (TP-048).
//   - Find the hook when the agent starts at boot before the system loads
//     /etc/pf.conf: a race for TP-046's service install to check.
//
// On a device the guard loads and passes its own check; that it blocks
// its leak paths is not yet proven on a device (TP-096).
package firewall
