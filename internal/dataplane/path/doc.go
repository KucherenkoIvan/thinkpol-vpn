// Package path is the path layer (docs/design/overlay.md "Data plane"): a WireGuard
// conn.Bind that gives WireGuard one stable endpoint per peer and picks
// between the peer's candidate paths underneath, and the relay that moves
// other nodes' packets along. It opens no socket (a lint rule holds it to
// that); everything travels over transport links to adjacent nodes.
//
// # Destination routing
//
// Relays, chains and device-to-device traffic are one mechanism: packets
// are routed by destination node id. A [Node] is one node's path layer. It
// keeps a link to every adjacent node its [Table] says to dial and takes
// the links adjacent nodes open to it ([Node.Serve]). Each WireGuard
// message travels in a packet frame with a header of [HeaderSize] bytes:
// destination node id, source node id, a hop limit, and the link's seq
// and ack (see frame.go for the layout; a relay writes its own seq and
// ack). The header sits inside the transport's seal, so none of it
// shows on the wire. A node receiving a packet:
//
//   - addressed to itself, hands it to the [Bind] that has the source as a
//     peer, or drops it;
//   - addressed to another node, forwards it along its [Route] for the
//     destination with one hop less (capped at its own hop limit), never to
//     the neighbor it came from, if it knows the source (a route to it, or
//     an adjacent node); anything else is dropped.
//
// A relay never decrypts what it forwards: it moves opaque WireGuard
// packets, and only to the destinations its section lists. The source id
// tells the destination which peer (and so which WireGuard device) a
// packet is for, and gives WireGuard an endpoint it can answer. Relays drop
// packets from sources they don't know; they already see those ids as the
// destinations of the replies. The source check is loose because the maps
// need not route both ways alike yet: a reply may come back through
// another hop than the one it was sent to. Once the map builder makes
// routes symmetric, it can become a strict reverse-path check.
//
// A sender starts a packet with [Options.HopLimit] hops ([DefaultHopLimit],
// 8), every relay caps what a packet keeps at its own limit and takes one
// off, and none forwards a packet that would arrive with none left. So a
// routing loop the maps contain ends after at most HopLimit-1 relays.
//
// Each relay's map section holds a forwarding table ([Table.Routes]): per
// destination, the adjacent next hops, several for a hop group in the
// middle of a chain, and a next hop may be the destination itself. A
// sender knows only its candidate first hops per peer ([Peer]): adjacent
// nodes, or the peer itself for a direct link. Each relay knows only its
// next hops, so no node holds a whole path. Device-to-device through a
// relay is a first hop whose route delivers to the other device; a chain
// ru-entry → nl-exit is the exit peer reached with ru-entry as its first
// hop, whose route leads to nl-exit. First hops and next hops come in
// priority order, the order [Failover] follows.
//
// # Liveness
//
// Links don't report liveness: a datagram link whose far end died just goes
// quiet. docs/design/path-liveness.md sets out the rules and their bounds;
// liveness.go is them. Every frame carries a per-link seq and the newest
// seq read from the far end (its ack), serial numbers inside the seal
// (frame.go). An answer is a frame whose ack is newer than any before or
// covers the latest frame written: proof that the far end reads this end.
// Received traffic alone proves only that the far end reaches this one.
//
// Busy: a frame that expects an answer (any but replies, close notices
// and WireGuard keepalives, told by length) written S after both the
// latest answer and the previous such frame opens a burst, due an answer
// within S + R; one written S after the latest answer within a burst is
// due one within R. S is drawn per answer from [Options.Burst], its top
// shrunk by D, both ends' shaping delay; R is the probes' smoothed round
// trip plus four deviations, clamped to [Options.Response]. Under two-way
// traffic acks keep coming and no probe goes. A link past its deadline is
// suspect: it probes at once, ahead of queued packets and through
// transport.WriteControl, and if no answer came by T/2 again, to its
// siblings too (its neighbor's other links, and the next up candidate of
// every peer and route on its neighbor), which turn suspect themselves.
// With no answer within T = 2·[Options.ControlHold] + D + R it closes,
// sending a close notice the far end obeys, and a dialed link is redialed
// through its endpoints in priority order with a backoff
// ([Options.RedialMin], [Options.RedialMax]). So a link dying under
// traffic is found within S + R + T of its last answer, 2.0–4.5 s
// unshaped. Packets moving to another of a neighbor's links, or a peer's
// to another first hop, make a link silent for R suspect at once.
//
// Idle: a link without an answer for I, drawn per wait from its
// transport's range ([Options.Idle]: 8–24 s on reality, 5–14 s on udp),
// turns suspect: one exchange per drawn wait, a dead idle link found
// within I + T. A link is up from its first answer until it closes.
// [Counters] counts liveness's own frames, probes, replies and close
// notices, written and read (ProbesSent, ProbesReceived), so that busy
// links sending none shows from outside (the lab's TP-080 checks).
//
// D is this end's shaping delay (transport.Shaping.MaxDelay), from the
// dial config or, on an accepted link, the link itself, doubled: the far
// end's isn't known here and is taken to be the same. Today's transports
// refuse delay shaping, so D is 0 on them.
//
// Older nodes read neither acks nor the newer frames: a link writes the
// older frames, every probe flagging that this end reads acks, and keeps
// the older rule (a probe every 2 s while unanswered that long, closed 6 s
// after its last answer) until the far end sends a probe with that flag
// or a newer frame. Replies don't count: older nodes copy flags back. A
// relay writes its own seq and ack; an older node's packet with no room
// for them goes on in the older format, neither counting nor answering.
//
// A link never answered closes after [Options.DialTimeout] (6 s by
// default). [Node.Neighbors] lists a dialed node that never gave a link as
// down once a dial attempt has failed (as with no route) or DialTimeout has
// passed since the dial started, whichever comes first, so a dial that
// never succeeds reads like a link that died; a first dial still waiting
// for an answer isn't listed before that. The deadline counts from the
// latest dial start: a map change of the node's endpoints restarts the
// dial, and the clock. Probe tokens are random, and a reply counts by its
// token only if it answers a probe still awaited. Its round trip is an
// upper bound: a transport that shapes may hold each probe and each reply
// up to transport.MaxControlHold, which T leaves room for. Latency
// comparisons belong on traffic nobody holds, such as WireGuard's
// handshake round trip.
//
// # Paths
//
// A [Bind] serves one WireGuard device. Its endpoints are peers' node ids;
// for every batch WireGuard sends, the peer's [Selector] picks one of its
// candidate first hops ([Choice], [Candidate]), by default [Failover].
// WireGuard's session is with the peer, not with the first hop, so
// switching first hops (entries of a chain) keeps the exit and the
// connections open through it. Traffic to an adjacent node stays on one of
// its links: the lower node id keeps its link while it is up, the higher
// sends where its latest answer came from. Packets are never spread across first
// hops packet by packet: they would arrive out of order, which TCP handles
// badly.
//
// [Failover] follows the priority order with hysteresis: it stays on the
// current hop while that is up, and a hop earlier in the order takes over
// only once it has been up for [Failover.HoldDown] (20 s by default), so a
// flapping primary doesn't pull traffic back and forth. Failover follows
// links only: a node notices its own first or next hop failing, and
// switches once the link is closed (above). A
// path that breaks further on goes unnoticed until end-to-end probes of
// each path come with hop groups (TP-031).
//
// Both ends of a pair choose, so one of them leads (the lower node id) and
// the other follows: on the next packet it sends, it takes the first hop
// the leader's latest authenticated packet came through, if that hop is up
// at its end too, and never returns to its primary on its own. A Bind
// learns that hop from WireGuard: the endpoints handed up with received
// packets name the first hop they came through, and WireGuard adopts an
// endpoint only from a packet it authenticated. Only a hop that is one of
// the peer's first hops counts, and only for [Options.FollowFor]. Cookie
// replies, which WireGuard sends before authenticating anything, neither
// move a choice nor count. Relays in the middle keep one next hop per
// destination and fail over on their own links with the same selector,
// without following.
//
// # Hop groups
//
// Not yet (TP-031): a chain hop that is a group (ru-entries) with a
// selection policy: failover (priority order), lowest-latency, or spread
// (each device sticks to one member, and devices are spread over the
// members). At the start of a chain the group becomes the device's
// candidate first hops, one per member; in the middle, a relay's next hops
// toward the exit. The path layer is to score the members (handshake
// success, loss, latency) and switch with hysteresis. Today the map can
// already list several first or next hops, and [Failover], the only
// [Selector], judges them on link liveness alone.
//
// # MTU
//
// [MessageBudget] is the largest WireGuard message a link carries under a
// transport's shaping: transport.MaxPacket less [HeaderSize], never more
// than [MaxMessageSize]. The layers above take WireGuard's own overhead off
// it for the TUN's MTU.
package path
