// Package supervisor runs on server nodes: one worker process per space,
// each in its own user, network, mount, PID, IPC, UTS and cgroup namespaces
// (see package worker), wired to the root namespace by a veth pair,
// restarted with backoff when it dies, and never outliving the supervisor.
// It also owns the node's public listeners for every space at once, and the
// root namespace's firewall that keeps the spaces apart and lets their
// egress out. See docs/design/server-agent.md "Server agent: one worker per space".
//
// # Slots and wiring
//
// Per worker slot n (stable while the space is served, reused after):
//
//	root namespace                         space's namespace
//	tp-space<n>  169.254.100.(4n+1)/30  ── veth0  169.254.100.(4n+2)/30
//	             fd74:7073:7061:<n>::1/64          fd74:7073:7061:<n>::2/64
//	                                       default routes via the root end
//	                                       (netcfg, OwnerSupervisor)
//
// The transit ranges are [DefaultTransitIPv4] (link-local, clear of an
// overlay's 100.64.0.0/10, of a provider's networks and of the metadata
// service address in 169.254.0.0/16) and [DefaultTransitIPv6] (unique local). The
// worker in slot n runs as host user and group [DefaultUIDBase]+n, a range
// above SSSD's id-mapping ceiling and below 2^31 that needs no passwd
// entry.
//
// Each worker process gets a fresh veth pair, created once the process
// exists and deleted with it: the root end lives exactly as long as the
// process's network namespace. The supervisor addresses both ends (no
// duplicate address detection), gives the space default routes via the
// root end through a [netcfg.Configurator] owned as
// [netcfg.OwnerSupervisor] (so the worker's own configurator can't take
// them), sets accept_ra 0 on the root end, and puts a permanent
// neighbour entry for the far end on both ends, so real traffic needs no
// ARP or ND. The worker has no /proc, so the supervisor also sets the
// space's network sysctls itself (loose reverse-path filtering, so the
// overlay's and relays' asymmetric paths aren't dropped, and forwarding,
// for egress): a thread of its own enters a private mount namespace and the
// space's network namespace and writes them through a fresh proc mount.
// Whether anything is forwarded is the space's own table's to say (see
// "Egress").
//
// # The worker process
//
// A worker is `thinkpol worker -space <id>`, the supervisor's own binary
// (/proc/self/exe, even once an update replaced the file; the IPC version
// in Init confirms it), fork+exec'd with an empty environment but the log
// level, in a fresh user namespace with its network, mount, PID, IPC, UTS
// and cgroup namespaces created inside it. The user namespace maps the
// worker's root to the slot's unprivileged host uid and gid, so the
// capabilities it carries across exec (as ambient capabilities:
// NET_ADMIN for its TUN, routes and nftables, NET_RAW for the data plane,
// NET_BIND_SERVICE for its DNS resolver on port 53, plus SYS_ADMIN and
// SETPCAP for setting up its sandbox) apply only inside its own
// namespaces and can't reach the root namespace through the veth's
// link-netnsid. The exec clears its supplementary groups and sets the
// parent-death signal (SIGKILL), from a thread locked for the process's
// whole life, so a worker never outlives the supervisor and its namespace
// dies with it. The worker then pivots into a minimal root, drops
// SYS_ADMIN and everything but the network capabilities, and sets
// no_new_privs (package worker).
//
// The worker talks to the supervisor over two unnamed SOCK_SEQPACKET
// socket pairs (package ipc): a control socket (Init, config, lifecycle,
// stream handoff) and a data socket (forwarded datagrams). The supervisor
// sends Init, waits for Ready (ReadyTimeout, 10 s by default) and only then
// routes traffic to the worker; Stop gives it StopTimeout (5 s) before a
// kill.
//
// A worker that exits is restarted with backoff ([DefaultBackoff]: 500 ms,
// doubling up to 30 s, back to 500 ms after a run of a minute), each time
// as a new process in fresh namespaces with a new veth pair. Its output
// goes to an in-memory ring per space (64 KiB), never to a disk; only the
// node owner's space's output also reaches the node's log.
//
// # Resource limits
//
// Each worker is started straight into a leaf cgroup of its own under
// /sys/fs/cgroup/thinkpol (cgroup v2, memory and pids controllers), kept
// across its restarts, with [Options.MemoryMax] and [Options.PidsMax] as
// memory.max and pids.max. Where cgroup v2 isn't available or the
// controllers aren't delegated, the supervisor says so in its log and runs
// workers without a cgroup. PidsMax also reaches the worker in Init, which
// sets it as its own RLIMIT_NPROC whether or not the cgroup exists; memory
// has no rlimit fallback.
//
// Not yet: production builds set no MemoryMax or PidsMax (the node agent
// builds Options without them), so a worker's cgroup has no limits and no
// rlimit is set; see TP-067.
//
// # The root namespace keeps the spaces apart
//
// A worker holds NET_ADMIN only inside its own user namespace, but it still
// owns its veth, so the separation can't rest on the spaces' routes or on
// the kernel trusting a space's packets. The supervisor's nftables tables
// in the root namespace ([TableName] in the inet family, [ArpTableName] in
// the arp family) are rebuilt from the whole set of slots on every change,
// in one atomic flush, before a new worker's veth carries a packet. They:
//
//   - anti-spoof each space to its own transit addresses at prerouting,
//     before conntrack sees its packets (priority raw - 10);
//   - drop what conntrack can't place (invalid, untracked) from a space;
//   - forward to a space's veth only established or related packets of a
//     conntrack entry whose original-direction source is that slot's
//     transit address (replies to its own flows), and drop everything else
//     forwarded to any space;
//   - send what a space forwards through its own chain (see "Egress");
//   - accept on input from a space only established packets of an entry
//     whose original-direction destination is that slot's address (the
//     root's own flows with it), and nothing "related": a forged "port
//     unreachable" or "fragmentation needed" never reaches the root's
//     sockets or its route cache;
//   - drop a space's ARP in the arp table; its ND has link-local sources,
//     which anti-spoof drops. Neither is needed, given the permanent
//     neighbour entries, and neither can flood the root's neighbour table.
//
// Anti-spoof and the binding of every accept to the slot that owns the
// conntrack entry are what isolate. Conntrack takes an ICMP error as
// "related" to whichever flow its inner header quotes, so a space quoting
// another space's flow, or a root flow, in an error it forges gets that
// flow's entry, which no accept of its own slot matches.
//
// Conntrack zones are belt and braces: what a space exchanges with its end
// of the veth pair (its gateway), what it broadcasts, and what the root
// namespace sends it are tracked in the slot's own zone (n+1), apart from
// the root's own flows in zone 0. What a space sends on (egress, its
// dials) stays in zone 0: replies arrive by the uplink before anything
// could tell their zone, and must find their flow to be un-NATed.
// (nftables can set a zone for the original direction only, which would
// solve that, but google/nftables can't express it, and "fib daddr type"
// isn't in every kernel.)
//
// Egress opens exactly what is masqueraded.
//
// # Egress
//
// Each space's traffic leaves through its own veth pair. Inside the space's
// namespace, the supervisor's table (thinkpol-space, family inet) forwards
// replies
// (established, related) and, only when the space has egress and the node
// an uplink, what goes out of veth0 in the families it may use; a family
// granted that the uplink doesn't carry is refused there with ICMP "no
// route", so clients fall back to the other at once (IPv6 on a VPS
// without it) instead of timing out. Without egress, forwarded traffic is
// dropped. The same table SNATs whatever leaves veth0 from another source
// (the overlay range) to the space's transit address, at a fully random
// port in [MasqueradePorts] (32768–60999). The worker owns that namespace
// and could change its table, so the root namespace enforces the same
// egress again.
//
// In the root namespace, the transit ranges are masqueraded wherever they
// leave but to a space, within the same port range, so all spaces exit
// from the node's public address (NAT66 for IPv6). The masquerade keeps
// the port the space's SNAT picked unless another flow holds it. Listeners
// can't bind inside the range ([Supervisor.SetListeners] refuses them), so
// no reply to a space's flow is taken for a connection to a listener, or
// the other way round. A transit source about to leave unmasqueraded is
// dropped (a filter chain after the NAT one).
//
// The uplink is the supervisor's: the interface of the root namespace's
// default route ([egress.FindUplink]), found again on every SetSpaces and
// whenever a default route changes (a route watcher, after 200 ms for a
// burst to settle). A name the tables can't match exactly counts as no
// uplink, and with no uplink no space has egress or dials. A space's grant
// ([Space.Egress], the families its map allows) counts in the families
// the uplink carries; IPv6 only with a global address, since unique local
// is no internet.
//
// What a space forwards goes, in the root's forward chain, through:
//
//   - a cap on its flows through the root namespace ([Options.MaxFlowsPerSpace];
//     by default a quarter of nf_conntrack_max, 65536 if that can't be
//     read): new ones over it are dropped, so one space can't fill the
//     node's conntrack table;
//   - destinations [Options.EgressAllowed] names (a network that is the
//     node's internet, such as a provider's or the lab's), which skip the
//     next step;
//   - a drop of the destinations no space reaches (see [EgressRefused]:
//     unspecified, loopback, multicast and reserved, link-local with the
//     cloud metadata services, Azure's wire server, RFC 1918, shared
//     address space with Alibaba's metadata address, ULA, IPv4-mapped)
//     and of the transit ranges;
//   - an accept out of the uplink, per family in its effective grant, and
//     for each of [Space.Dials] (the endpoints its own section dials:
//     relays, chains) by address, protocol and port whatever its egress;
//     each only for the space's own flows (original-direction source its
//     transit address). Everything else is dropped.
//
// Replies come back as established flows bound to the space's transit
// address. When a space's effective egress changes, its namespace's table
// is rewritten and the conntrack entries its transit addresses started are
// flushed, so no old flow carries on; the same when a slot is freed.
//
// Other tables' drops still win (a container runtime's or a host
// firewall's FORWARD policy): provisioning's concern.
//
// # Root forwarding
//
// Where the root namespace doesn't forward a family some space needs (by
// egress or a dial), the supervisor turns it on, and only then: a node that
// forwards already (a container runtime, its own routing) is left alone,
// and its forwarding isn't the supervisor's to confine. What it turned on
// it confines to the spaces' traffic (the forward chain drops everything
// else of that family), the tables being in place before the switch is
// flipped. Before IPv6 forwarding it sets accept_ra 2 on every interface
// where it is 1, since forwarding makes Linux ignore router advertisements
// at 1, which would cost an RA-configured uplink its default route.
// Turning forwarding on resets other sysctls (IPv4: accept_redirects and
// every interface's forwarding; IPv6: every interface's forwarding), and
// turning it off resets them again, so the record keeps their earlier
// values.
//
// It records what it changed in [DefaultRuntimeDir] (forwarding.json, on a
// tmpfs like the sysctls' own lifetime), so a successor after a crash
// adopts the families whose switch still holds what was written. It puts
// everything back, side effects included and each only if still unchanged
// since, when no space needs it and on Close, before it removes its
// tables, never the other way round, or the root would forward everything
// for a moment. Forwarding it can't turn off keeps its tables and its
// record, so the root still forwards nothing else and the next start tries
// again.
//
// # Shared listeners
//
// The supervisor owns the node's public address, the scarce resource, and
// listens on the node owner's map's listeners for every space it serves
// ([Supervisor.SetListeners]; guest spaces never open ports). It accepts
// whatever arrives, runs the transport's authentication (its router, a
// [transport.PacketRouter] or [transport.StreamRouter], one per transport,
// shared by all its listeners and kept across their reopens, so replay
// state is per credential, not per socket), maps the credential to a
// space and hands the traffic to that space's worker. The credential tables are the spaces' [Space.Inbound],
// each dataplane.AcceptedInbound of the space's own section, merged per
// transport, with each entry's Space stamped with the space whose map it
// came from, never what the map says. Two links sharing a secret, in one
// space or two, are both rejected rather than one guessed
// ([ListenerInfo.Rejected]). The tables change before the workers do: a
// space leaving is unreachable before its worker stops, and a new one
// routable once its worker is ready.
//
// Whatever fails authentication, is stale or replayed, or authenticates as
// a space no longer served goes to the listener's [Listener.Camouflage],
// and never reaches a worker. On a node with ingress off,
// dataplane.AcceptedInbound keeps only other servers' links, so a
// device's credential is unauthenticated there and gets the camouflage,
// whatever inbound links the section lists. Not yet: the node agent
// passes no Camouflage, so all of it is dropped ([transport.Drop]).
//
// # Datagrams
//
// A datagram transport's connection id tells the Router which credential
// to check; it authenticates the datagram, checks its timestamp and
// filters replays per credential (the transport's own sender windows),
// then the supervisor forwards it, untouched, to the space's current
// worker over the worker's data socket without blocking: a full socket
// drops the datagram (counted as WorkerFull), so a stuck worker stalls
// only its own space. A replay needs only a passive tap to capture, so
// within one supervisor's lifetime it is dropped before it reaches a
// worker or costs its space anything (RESIDUAL-RISKS.md RR34). The worker
// decrypts and filters again.
//
// The worker's replies come back over the same socket and leave through
// the public socket it names, but only to a source address that one of the
// space's own authenticated, fresh, non-replayed datagrams came from,
// through that listener, in the last 2 minutes (the address is refreshed
// by each such datagram, remembered before the hand-off, since the worker
// is another process and may answer before the hand-off returns, and kept
// even when the worker's socket refuses the datagram; expiry is swept
// every 10 s, and checked exactly on send). Each link keeps its latest 8
// such addresses, a new one evicting that link's oldest, so no link can
// displace another's. A worker can answer its peers, never use the node's
// public address to reach anyone else, whatever egress its space has.
//
// Not after a supervisor restart: Routers and reply addresses live in
// memory, the workers die with the supervisor, and a replay of datagrams
// sent in the last five minutes (ten, if the sender's clock ran ahead) is
// routed and answered again (RESIDUAL-RISKS.md RR34; TP-069).
//
// # Streams
//
// A stream transport's Router reads the start of each connection; an
// authenticated one's descriptor and the bytes already read go to the
// space's worker over its control socket, without blocking (a full socket
// refuses the connection). A listener routes at most 1024 connections at
// a time, each given at most 10 s to show who it is; past the bound a
// connection goes straight to the camouflage. No stream transport exists
// yet.
//
// # Fair share
//
// [FairShare] is the hook for each guest space's bandwidth cap (token
// buckets per space, or tc classes per veth) and for splitting spare
// capacity under load: the shared listeners ask Allow before forwarding a
// datagram or sending a reply, and Charge once the worker's socket
// accepted it or it went out. A handed-over stream's bytes never pass
// through the supervisor, so its cap sits elsewhere: a pacing rate set on
// the socket before the handoff limits only what the node sends on it;
// uploads need policing (tc ingress, or an IFB device) or a read-rate
// limit. Not yet: production builds pass no FairShare; see TP-040
// (parked).
//
// # The gatekeeper (planned)
//
// Today the supervisor, a root process holding every space's credential
// tables, parses unauthenticated bytes itself: datagram authentication,
// timestamp and replay filtering, and the start of each stream
// connection. That is the known weakness of the current design. Planned:
// everything that parses unauthenticated bytes (the ClientHello peek,
// datagram authentication, timestamp and replay filtering) moves to an
// unprivileged gatekeeper process, sandboxed like a worker, with no space
// keys beyond what verification needs, so a memory-safety bug in that path
// costs the gatekeeper, not the supervisor. The gatekeeper hands what it
// authenticates to the worker the way the supervisor does today (file
// descriptors, forwarded datagrams); the supervisor keeps the namespaces,
// the root firewall and fair share.
//
// What the gatekeeper holds depends on the transport. For `tls` the
// credentials should be asymmetric (the map gives listeners a public key
// to verify, not a shared secret), so a listener's holder can't forge a
// client. A symmetric transport (`udp`) still needs a secret per
// credential, and the gatekeeper is where it lives. `reality` is the
// exception: opening its session id needs the listener's X25519 private
// key, so a `reality` listener's gatekeeper holds that key. In order:
// TP-063 for `udp` (M2), TP-088 for `reality`, and `tls`'s part with
// TP-028 (after the MVP).
package supervisor
