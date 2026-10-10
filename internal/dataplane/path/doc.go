// Package path is the path layer (DESIGN.md "Data plane"): a WireGuard
// conn.Bind that gives WireGuard one stable endpoint per peer and picks
// between the peer's candidate paths underneath, and the relay that moves
// other nodes' packets along. It opens no socket (a lint rule holds it to
// that); everything travels over transport links to adjacent nodes.
//
// # Destination routing
//
// A [Node] is one node's path layer. It keeps a link to every adjacent node
// its [Table] says to dial and takes the links adjacent nodes open to it
// ([Node.Serve]). Each WireGuard message travels in a packet frame with a
// header of [HeaderSize] bytes: destination node id, source node id and a
// hop limit (see frame.go for the layout). A node receiving a packet:
//
//   - addressed to itself, hands it to the [Bind] that has the source as a
//     peer, or drops it;
//   - addressed to another node, forwards it along its route for the
//     destination with one hop less (capped at its own hop limit), never to
//     the neighbor it came from, if it knows the source (a route to it, or
//     an adjacent node); anything else is dropped.
//
// A relay never decrypts what it forwards, and forwards only to the
// destinations its section lists. No node holds a whole path: a sender knows
// a peer's candidate first hops, each relay only its next hops. The source
// id tells the destination which peer (and which WireGuard device) a
// packet is for, and gives WireGuard an endpoint it can answer. The source
// check is loose because maps need not route both ways alike: a reply may
// come back through another hop than the one it was sent to.
//
// # Liveness
//
// Links don't report liveness: a datagram link whose far end died just goes
// quiet. Both ends of a link probe it when their last proof is older than
// [Options.ProbeInterval], ahead of queued packets and through
// transport.WriteControl; a link is up while a reply to one of its own
// probes came back within [Options.DeadAfter], proof that both directions
// work. A link without proof for DeadAfter is closed, and a dialed link is
// redialed through its endpoints in priority order with a backoff. Probe
// tokens are random, and a reply counts only if it answers a probe still
// awaited; its round trip is an upper bound (shaping may hold probes).
//
// Failover follows these links only: a node notices its own first or next
// hop failing, not a failure further on. End-to-end probing of each path is
// TP-031's.
//
// # Paths
//
// A [Bind] serves one WireGuard device. Its endpoints are peers' node ids;
// for every batch WireGuard sends, the peer's [Selector] picks one of its
// candidate first hops ([Choice], [Candidate]), by default [Failover].
// WireGuard's session is with the peer, whatever the path, so a switch
// never breaks it. Traffic to an adjacent node stays on one of its links
// while that link is up.
//
// Both ends of a pair choose, so one of them leads (the lower node id) and
// the other follows: it takes the first hop the leader's latest
// authenticated packet came through, and never returns to its primary on
// its own. A Bind learns that hop from WireGuard: the endpoints handed up
// with received packets name the first hop they came through, and
// WireGuard adopts an endpoint only from a packet it authenticated. Only a
// hop that is one of the peer's first hops counts. Cookie replies, which
// WireGuard sends before authenticating anything, neither move a choice nor
// count. Relays in the middle keep one next hop per destination and fail
// over on their own links with the same selector, without following.
package path
