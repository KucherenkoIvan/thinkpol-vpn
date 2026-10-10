// Package transport is the port for one link between two adjacent nodes:
// authentication, framing and traffic shape (DESIGN.md "Data plane",
// "Transports own traffic shape"). Each transport is an adapter in its own
// subpackage, transport/<name>; transport/transporttest is the conformance
// suite every adapter passes, and transport/memory is an in-process adapter
// for tests of the layers above.
//
// # Links
//
// A [Link] carries whole packets of 1 to [MaxPacketSize] bytes in both
// directions. Delivery is best effort: a link may drop or reorder packets
// (a stream transport does neither) but never splits, merges or alters them,
// and never delivers a packet its peer didn't write. Replays are filtered as
// the adapter documents; WireGuard's own replay protection is the guarantee.
// All methods are safe for concurrent use.
//
// WritePacket may block for backpressure. Close unblocks pending reads and
// writes. An error matching [net.ErrClosed] is final: the link is closed,
// locally, by its listener (with [ErrRevoked] or [ErrSuperseded] as the
// cause), or by the adapter itself when it hit an error it can't recover
// from ([ClosedError] with that error as the cause). Any other error loses
// only the packet at hand. Liveness is not the transport's business: a
// datagram link whose peer went away simply stops delivering, and the path
// layer above notices and redials.
//
// # Dialing and listening
//
// A [Dialer] opens a link to an endpoint with the [DialConfig] the map gives
// for that link. Endpoints are IP literals: the controller resolves names,
// nodes never do at dial time. Dial may return before the far end has seen
// anything (datagram transports have no handshake); a dial with a
// credential the far end doesn't accept either fails or yields a link that
// never delivers.
//
// A [Listener] accepts links from the peers in its [Peers] table and reports
// who each one is ([Identity]: space id and node id). It authenticates before
// revealing anything: whatever fails authentication, including the replays
// it catches, goes to the listener's [Camouflage], so an unauthenticated
// peer sees only what the camouflage shows it (for udp, silence). A listener
// keeps at most one link per credential. When the same credential dials
// again, either the new link replaces the old one, which closes with
// [ErrSuperseded] (stream transports), or the existing link carries on and
// follows the dialer (datagram transports without a handshake). When the
// table changes, links whose credential is gone are closed ([ErrRevoked]);
// links whose credential stays pick up their new settings. Accept may
// return a link that is already closed. Closing a listener closes every link
// it accepted; a dialer's link either carries on with a listener restarted
// at the same endpoint or closes, so the layer above redials.
//
// Each direction of a pair of nodes is its own link with its own
// credential: A dialing B and B dialing A must never share a secret.
//
// # The map and the engine
//
// What the map says about a link arrives as a [DialConfig] (dialing end) or
// a [PeerLink] (listening end), and about a listener as a [ListenConfig].
// Each transport's settings are its own protobuf messages in
// proto/thinkpol/transport/v1: the controller encodes them, the adapter
// decodes them, and everything else passes them as bytes. The conversion
// from the map to these types is the data-plane engine's (package
// dataplane), which checks every entry with the [Transport]'s
// CheckEndpoint and CheckInbound and finds transports by name in a
// [Registry] built in the composition root.
//
// Traffic shape (padding, batching, timing) belongs to the transport, never
// to the layers above (C6); [Shaping] is where its settings go.
//
// # Shared listeners
//
// On a server node the supervisor owns the public address for every space
// (DESIGN.md "Server agent: one worker per space"). A [Routable] transport
// gives it a [Router], which authenticates each datagram or the start of
// each connection and says which space's worker it belongs to. Datagram
// transports' workers listen on what the supervisor forwards; stream
// transports' workers are a [HandoffListener].
package transport
