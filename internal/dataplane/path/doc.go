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
// destination node id, source node id and a hop limit (see frame.go for
// the layout). The header sits inside the transport's seal, so none of it
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
// quiet. Both ends of a link probe it when their last proof is older than
// [Options.ProbeInterval] (2 s by default), ahead of queued packets and
// through transport.WriteControl; a link is up while a reply to one of its
// own probes came back within [Options.DeadAfter] (three probe intervals,
// 6 s, by default), proof that both directions work. A link without proof
// for DeadAfter is closed, and a dialed link is redialed through its
// endpoints in priority order with a backoff ([Options.RedialMin],
// [Options.RedialMax]). Probe tokens are random, and a reply counts only if
// it answers a probe still awaited. Its round trip is an upper bound: a
// transport that shapes may hold each probe and each reply up to
// transport.MaxControlHold, which DeadAfter must leave room for. Latency
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
// its links while that link is up. Packets are never spread across first
// hops packet by packet: they would arrive out of order, which TCP handles
// badly.
//
// [Failover] follows the priority order with hysteresis: it stays on the
// current hop while that is up, and a hop earlier in the order takes over
// only once it has been up for [Failover.HoldDown] (20 s by default), so a
// flapping primary doesn't pull traffic back and forth. Failover follows
// links only: a node notices its own first or next hop failing, and
// switches within about one dead interval of the last answered probe. A
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
