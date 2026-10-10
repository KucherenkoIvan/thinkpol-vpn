// Package transport is the port for one link between two adjacent nodes:
// authentication, framing and traffic shape (DESIGN.md "Data plane",
// "Transports own traffic shape"). Each transport is an adapter in its own
// subpackage, transport/<name>; transport/transporttest is the conformance
// suite every adapter passes, and transport/memory is an in-process adapter
// for tests of the layers above.
//
// # Contract
//
// A [Link] carries whole packets of 1 to [MaxPacketSize] bytes in both
// directions. Delivery is best effort, as with datagrams: a link may drop or
// reorder packets but never splits, merges or alters them, and never delivers
// a packet that its peer didn't write (no forgeries, no replays). All methods
// are safe for concurrent use. Once a link is closed, locally or by its
// listener, ReadPacket and WritePacket return an error matching
// [net.ErrClosed]; when the listener closed it because its credential was
// revoked or a newer link replaced it, the error also matches [ErrRevoked] or
// [ErrSuperseded]. Liveness is not the transport's business: a datagram link
// whose peer went away simply stops delivering, and the path layer above
// notices.
//
// A [Dialer] opens a link to an endpoint with the [LinkConfig] the map gives
// for that link. Dial may return before the far end has seen anything
// (datagram transports have no handshake); a dial with a credential the far
// end doesn't accept either fails or yields a link that never delivers.
//
// A [Listener] accepts links from the peers in its [Peers] table and reports
// who each one is ([Identity]: space id and node id). It authenticates before
// revealing anything: whatever fails authentication, including replays, goes
// to the listener's [Camouflage], so an unauthenticated peer sees only what
// the camouflage shows it (for udp, silence). A listener keeps at most one
// link per credential: a newer link with the same credential closes the
// older one ([ErrSuperseded]). When the table changes, links whose credential
// is gone are closed ([ErrRevoked]). Closing a listener closes every link it
// accepted.
//
// Credentials and shaping come per link from the map ([LinkConfig]). Traffic
// shape (padding, batching, timing) belongs to the transport, never to the
// layers above (C6); [Shaping] is where its settings go.
package transport
