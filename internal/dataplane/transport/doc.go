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
// a packet its peer didn't write. Replays are filtered on a best-effort basis
// (a datagram transport's window forgets on restart); WireGuard's own replay
// protection is the guarantee. All methods are safe for concurrent use. Once
// a link is closed, locally or by its listener, ReadPacket and WritePacket
// return an error matching [net.ErrClosed]; when the listener closed it
// because its credential was revoked or a newer link replaced it, the error
// also matches [ErrRevoked] or [ErrSuperseded]. Liveness is not the
// transport's business: a datagram link whose peer went away simply stops
// delivering, and the path layer above notices and redials.
//
// A [Dialer] opens a link to an endpoint with the [LinkConfig] the map gives
// for that link. Dial may return before the far end has seen anything
// (datagram transports have no handshake); a dial with a credential the far
// end doesn't accept either fails or yields a link that never delivers.
//
// A [Listener] accepts links from the peers in its [Peers] table and reports
// who each one is ([Identity]: space id and node id). It authenticates before
// revealing anything: whatever fails authentication, including replays it
// catches, goes to the listener's [Camouflage], so an unauthenticated peer
// sees only what the camouflage shows it (for udp, silence). A listener keeps
// at most one link per credential. When the same credential dials again,
// either the new link replaces the old one, which closes with
// [ErrSuperseded] (stream transports), or the existing link carries on and
// follows the dialer (datagram transports without a handshake). When the
// table changes, links whose credential is gone are closed ([ErrRevoked]).
// Closing a listener closes every link it accepted; a dialer's link either
// carries on with a listener restarted at the same endpoint or closes, so
// the layer above redials.
//
// Credentials and shaping come per link from the map ([LinkConfig]). Traffic
// shape (padding, batching, timing) belongs to the transport, never to the
// layers above (C6); [Shaping] is where its settings go.
package transport
