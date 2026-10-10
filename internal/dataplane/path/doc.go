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
//     peer, if it came through one of that peer's first hops, or drops it;
//   - addressed to another node, forwards it along its route for the
//     destination with one hop less (capped at its own hop limit), if it
//     came from its source or from a next hop of the route back to its
//     source, and never to the neighbor it came from; anything else is
//     dropped.
//
// A relay never decrypts what it forwards, and forwards only to the
// destinations its section lists. No node holds a whole path: a sender knows
// a peer's candidate first hops, each relay only its next hops. The source
// id tells the destination which peer (and which WireGuard device) a
// packet is for, and gives WireGuard an endpoint it can answer; relays
// check it by reverse path, so a neighbor can't claim a source it has no
// business carrying. They already see the source on the first link, and the
// same ids as destinations of the replies further on.
//
// # Liveness
//
// Links don't report liveness: a datagram link whose far end died just goes
// quiet. The dialing end of a link probes it when it hasn't both sent and
// received within [Options.ProbeInterval]; the other end answers. Every
// frame received counts as a sign of life, data as much as probe replies.
// A link that has heard nothing for [Options.DeadAfter] is down and is
// closed, and a dialed link is redialed through its endpoints in priority
// order with a backoff. Probe tokens are random and a reply counts for the
// round trip only if it answers a probe still awaited.
//
// That covers the first hop. A first hop whose links are fine can still
// lead nowhere; until paths are probed end to end, a Bind that keeps
// sending a peer through one first hop with nothing delivered from the peer
// demotes that hop for the peer ([Options.E2EDead]).
//
// # Paths
//
// A [Bind] serves one WireGuard device. Its endpoints are peers' node ids;
// for every batch WireGuard sends, the peer's [Selector] picks one of its
// candidate first hops from their state ([Candidate]), by default
// [Failover]. WireGuard's session is with the peer, whatever the path, so
// a switch never breaks it. Traffic to an adjacent node stays on one of its
// links while that link is up.
//
// Both ends of a pair choose, so one of them follows: the end with the
// higher node id takes the first hop the other end's traffic comes
// through. A Bind learns it from WireGuard: the endpoints handed up with
// received packets name the first hop they came through, and WireGuard
// adopts an endpoint only from a packet it authenticated. Relays in the
// middle keep a choice per destination with the same machinery, following
// the destination's path when the destination is the lower id of the pair.
// Cookie replies, which WireGuard sends before authenticating anything,
// neither move a choice nor count as a sign of life.
package path
