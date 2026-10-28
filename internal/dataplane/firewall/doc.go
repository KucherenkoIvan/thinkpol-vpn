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
// switch (docs/design/security.md "Kill switch"). Forwarded traffic isn't its business:
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
// is in place again compares the table with what it wants and rebuilds it
// if anything differs: its flags, none (a dormant table keeps its rules
// but its chains are unhooked: no guard at all); its chains, exactly one,
// `output` as hooked (another base chain in it could set the links' mark
// before the guard's sees the packet); every rule's expressions in order,
// counters aside; and every set element, in any order (an element added
// is a leak, one removed a refusal). The table stays when the
// process dies, so a crash leaves IPv6 confined as the route table's
// unreachable default does; [IPv6Guard.Close] removes it, and a fresh
// guard's Close removes a crashed run's.
//
// [IPv6Guard.Watch] subscribes to nftables' events and signals, coalesced,
// whenever something of the guard's table changes from outside: a
// deletion (a table, chain, rule or set: `nft flush ruleset`, a firewall
// service's reload), the table updated (made dormant), a chain added or
// updated (its policy), a rule added or replaced, a set element added or
// removed. When the socket overflows (events may have been lost) it
// signals at once and again a second later. The Enforcer then re-applies
// the guard, so it is right again within about a second. The guard's own
// Apply shows up too, and finds the table whole.
//
// What the comparison and the watch don't catch (RESIDUAL-RISKS.md RR11):
// other tables. The guard trusts the links' mark, and checks only its own
// table for who sets it, so a base chain in another table that sets the
// mark at output before the guard's chain lets IPv6 out of a physical
// interface, and isn't seen.
//
// The guard's first request is a dump of the inet tables. Its answer, and
// only its answer, can make the guard unsupported: an error meaning no
// nf_tables in the kernel (EPROTONOSUPPORT, EAFNOSUPPORT, EOPNOTSUPP,
// EINVAL) wraps [routetable.ErrGuardUnsupported]. Any other error, and
// any error of a later request (an EOPNOTSUPP ack to a batch included),
// is an ordinary failure, retried; until the dump succeeds once, each
// request asks again. On such a kernel Close has nothing to remove.
//
// # Linux: reading it back
//
// [InspectIPv6Guard] reads the table as the kernel holds it, for
// diagnostics, whether or not a guard runs: its flags (a dormant table
// guards nothing; the kernel sends the flags big-endian, which nftables
// decodes in the host's order), its chains as hooked (unreadable on their
// own if they can't be listed), each rule's expressions rendered nft-like
// (raw payloads in nft's `@base,offset,length` bits; an expression the
// renderer doesn't know shows as its type, so the text is no nft input)
// with its counter's values, and the exempt set's intervals as the fewest
// prefixes. No table is no guard, and a table without the set exempts
// nothing: neither is unreadable; a kernel without nf_tables is.
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
// en0`, `inet`, doesn't count), nothing is loaded or enabled and the
// apply fails, an ordinary failure: the health says
// `ipv6_guard_not_enforced`, and the route table retries (every 5 s, and
// on the guard's 10 s poll, which reports a failed apply), so the guard
// goes in within seconds of the hook being there. The system loads
// /etc/pf.conf as it boots, and an agent its service starts then
// (connect-on-boot) may come first; a main ruleset replaced without the
// hook may get it back. The device stays connected meanwhile, its routes
// in place: only interface-bound IPv6 is unconfined until the hook is
// there, where waiting to connect would send everything direct.
//
// With the hook there, three things still let IPv6 past the anchor, and
// while one lasts the guard isn't enforced (`ipv6_guard_not_enforced`,
// retried):
//
//   - a `pass ... quick` above the hook that an outgoing IPv6 packet could
//     match (not `in` only, not `inet` only): evaluation ends there;
//   - an interface pf skips (`set skip on`) but lo0 and the utun, which
//     the anchor passes anyway: pf evaluates no rule for its packets, and
//     `-s rules` doesn't show it; `pfctl -s Interfaces -v` lists it as
//     "<name> (skip)". The guard counts every name listed so, on purpose:
//     whether pf lists a name no interface has (`set skip on lo`, a
//     group), or marks the interfaces it prefixes (lo0), is for TP-096 to
//     check on a Mac;
//   - an anchor under com.apple whose name sorts before the guard's
//     (`pfctl -a com.apple -s Anchors`): pf keeps anchors sorted by path,
//     so it runs first, and a quick pass in it ends evaluation there. Its
//     existence counts, not its rules; a stock Mac is expected to have
//     only Apple's two (TP-096 checks).
//
// These are checked last in every apply, after the load and the enable,
// so what pf does filter stays guarded meanwhile, and in every poll. The
// guard reports them; it doesn't undo other software's pf settings.
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
// (its state policy is floating). So the guard lists the states (`pfctl
// -s states`) and kills the IPv6 ones whose other end isn't in the exempt
// table, each by its two ends, `pfctl -k <host's end> -k <other end>` and
// the reverse; states to exempt destinations and IPv4 ones are left
// alone. An upstream's address isn't exempt for this: `-k` names hosts,
// not ports, so its states go too, and DNS goes on through its stateless
// rule. Killing a tunnelled connection's state is harmless the same way:
// the anchor passes it statelessly.
//
// It kills them after a load and after enabling pf (states from before),
// and after an apply that failed (a quick pass above the hook keeps state
// by default, and its states outlive it), with one exception: while the
// same bypasses last (checkBypass's verdict unchanged), the retries don't
// kill again. What a bypass lets through needs no state, and the anchor
// lets nothing outgoing make one, so a kill would only take what the
// bypass makes anew. A change checkBypass's verdict shows (a kind of
// bypass more or gone, a skipped interface or an earlier anchor more or
// gone, all gone) kills them, taking what the one gone let be made; a
// second quick pass above the hook, or an earlier anchor's rules changing
// under the same name, doesn't change the verdict, and its states live on
// until the verdict changes, a reload or an enable. A bypass that comes
// and goes between two polls is seen by no apply, and its states live on
// (RESIDUAL-RISKS.md RR11).
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
// lists it; if that release fails, the Apply finishes enforcing (the
// bypass check, the state kill), then says so (the record names the new
// reference, and the old one is left to pf).
//
// `pfctl -s References` is read by the columns its header names: a line's
// first field is the pid, and the token is the field where the header's
// TOKEN starts, whatever the process name (spaces included) and the
// timestamp look like. While pf holds no reference, pfctl prints only "No
// pf starter references held", without the header, and nothing but its
// ALTQ chatter on stderr: a listing of none. A listing without the header
// otherwise, a header with no reference under it, a line out of those
// columns, one cut short, or that answer with anything else on stderr is
// one the guard can't read, and a reference not
// found in it proves nothing: looking a token up by pid and
// releasing both fail, so the record stays and the next Close (or
// routetable.Clear's) tries again. pf stays enabled on that reference
// meanwhile, rather than the guard forgetting a reference pf still holds.
//
// # macOS: polling
//
// pf has no event stream, so [IPv6Guard.Watch] polls every 10 s: the hook,
// what bypasses it (the skipped interfaces, the anchors under com.apple),
// the anchor's rules and table, and pf enabled (six pfctl runs, each
// bounded at 15 s), and whether its last apply failed, so a retry is due.
// The Enforcer then puts back what changed: `pfctl -d`, a flush, an entry
// added, a replaced main ruleset that still has the hook are undone within
// about 10 s, not a second as on Linux; a bypass is reported within as
// long. A main ruleset replaced without the hook fails the guard until the
// hook is back.
//
// # macOS: crashes and reboots
//
// The anchor and the reference stay when the agent dies, so a crash
// leaves IPv6 confined, as the route table's reject routes do (fail
// closed). The next start's [routetable.Clear], under the route table's
// owner lock, closes a fresh guard, which flushes the anchor's rules and
// table (`-F rules`, `-F Tables`: `-F all` would also flush pf's global
// state table and statistics; after each flush, whatever pfctl answered,
// the anchor is listed: it counts as empty once it lists no rule and pf
// answers that the guard's table doesn't exist) and releases the recorded
// reference. A guard that applies instead takes that reference over. The
// anchor goes before the reference, so pf is never left off with the
// anchor still meant to be in place. A reboot takes both, and the record,
// stamped with an earlier boot, is dropped without releasing anything.
// [IPv6Guard.Apply] and [IPv6Guard.Close] change pf, and only the
// Enforcer calls them, holding its owner lock; Watch only reads.
//
// # macOS: reading it back
//
// [InspectIPv6Guard] reads the guard as pf holds it, for diagnostics,
// running listings only (`-s ...`, a table's `-T show`; never a load,
// -E, -X, -F, -k, -d or -z) and opening the record's directory without
// making it: the anchor's rules with their counters (`-s rules -v`: each
// rule's line, its "[ Evaluations: ... Packets: ... Bytes: ... States:
// ... ]" line, and the optional "[ Inserted: ... ]" line, with or without
// "State Creations"), the exempt table, `-s info`'s Status line, and what
// the guard's check reads (readBypass, shared with checkBypass): its
// verdict on the main ruleset with the lines up to the hook as evidence,
// every name pf skips, the anchors before the guard's. Then the record's
// reference, by its pid, with whether `-s References` lists it as taken by
// that pid; the token stays in the record. A listing with a line it can't
// read (no rule, counters out of place, unreadable or past uint64, a rule
// without counters, a line too long to read; in References, as the guard
// reads it, above) is unreadable as a whole, naming the line: half a listing
// could hide the rule that matters. A record of another boot is stale;
// one that isn't a regular file or can't be parsed is unreadable, said in
// fixed words (trusteddir's errors never quote a record either). A
// missing anchor is an empty one, and with no pfctl at all everything is
// unreadable.
//
// Guard and snapshot alike, pfctl's answers of absence are each one exact
// line, alone on stderr but for its ALTQ chatter (its two exact lines, "No
// ALTQ support in kernel" and "ALTQ related functions disabled"; a rule's
// label saying ALTQ is a rule): a missing anchor's
// rules, `pfctl: DIOCGETRULES: Invalid argument` ([AnchorMissing]); a
// missing table, `pfctl: Table does not exist.` (macOS answers it for a
// missing anchor's table too) or `pfctl: Anchor or Ruleset does not
// exist.`. Any other failure, an "Invalid argument" of another ioctl
// included, is an error, never an empty anchor or table. The parsers are
// tested on listings a Mac printed (testdata/pfctl/recorded-*, sanitized),
// and on built ones for what no device has printed.
//
// # What the macOS guard doesn't do
//
//   - Match MLD's hop limit (above).
//   - See a quick pass inside an anchor the main ruleset evaluates before
//     the hook (TP-129). An anchor under com.apple that sorts before the
//     guard's is seen (above).
//   - Undo what lets IPv6 past it (above): it reports it.
//   - Confine IPv4: that is the kill switch's (TP-048).
//   - Confine interface-bound IPv6 while the main ruleset has no hook (at
//     boot, before the system has loaded /etc/pf.conf; or replaced): it
//     waits for the hook.
//
// On a device the guard loads and passes its own check; that it blocks
// its leak paths is not yet proven on a device (TP-096).
package firewall
