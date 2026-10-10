// Package path is the path layer (DESIGN.md "Data plane"): a WireGuard
// conn.Bind that gives WireGuard one stable endpoint per peer and picks
// between the peer's candidate paths underneath, and the relay that moves
// other nodes' packets along. It opens no socket; everything travels over
// transport links to adjacent nodes.
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
//     destination to an adjacent next hop (in priority order, skipping
//     next hops with no live link and the neighbor it came from), with one
//     hop less, or drops it: no route, no hops left, no link.
//
// A relay never decrypts what it forwards, and forwards only to the
// destinations its section lists. No node holds a whole path: a sender knows
// a peer's candidate first hops, each relay only its next hop. The source
// id is there so the destination can tell WireGuard which peer a packet is
// from; relays already see it on the link for the first hop, and a relay
// further on sees the same ids as destinations of the replies.
//
// # Liveness
//
// Links don't report liveness: a datagram link whose far end died just goes
// quiet. The dialing end of a link probes it when it hasn't both sent and
// received within [Options.ProbeInterval]; the other end answers. A link
// that has heard nothing for [Options.DeadAfter] is down and is closed, and
// a dialed link is redialed, through its endpoints in priority order with a
// backoff. Probe round trips are smoothed per link.
//
// # Paths
//
// A [Bind] serves one WireGuard device. Its endpoints are peers' node ids;
// for every batch WireGuard sends, the peer's [Selector] picks one of its
// candidate first hops from their state ([Candidate]), by default
// [Failover]. WireGuard's session is with the peer, whatever the path, so
// a switch never breaks it. The endpoints handed up with received packets
// also name the first hop the packet came through; WireGuard adopts an
// endpoint only from a packet it authenticated, so what it sends to tells
// the Selector which path the peer is using, and Failover follows it.
package path
