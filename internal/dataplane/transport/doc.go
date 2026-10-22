// Package transport is the port for one link between two adjacent nodes:
// authentication, framing and traffic shape (docs/design/overlay.md "Data plane",
// docs/design/transports.md "Transports own traffic shape"). Each transport is an adapter in its own
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
// locally, by its listener (with [ErrRevoked], [ErrSuperseded] or
// [ErrSettingsRefused] as the cause), or by the adapter itself when it hit
// an error it can't recover from ([ClosedError] with that error as the
// cause). Any other error loses
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
// links whose credential stays pick up their new settings, or close with
// [ErrSettingsRefused] if the transport refuses them. Accept may
// return a link that is already closed. Closing a listener closes every link
// it accepted; a dialer's link either carries on with a listener restarted
// at the same endpoint or closes, so the layer above redials.
//
// Each direction of a pair of nodes is its own link with its own
// credential: A dialing B and B dialing A must never share a secret.
//
// # The map and the engine
//
// The map says, the engine converts, the transport decides. What the map
// says about a link arrives as a [DialConfig] (dialing end) or a
// [PeerLink] (listening end), and about a listener as a [ListenConfig].
// Each transport's settings (listener, dial side, inbound side) are its own
// protobuf messages in proto/thinkpol/transport/v1: the controller encodes
// them, the adapter decodes them, and the map and everything between carry
// them as opaque bytes. The conversion from the map to these types is the
// data-plane engine's (package dataplane), not netmap's or the adapters':
// it finds transports by name in a [Registry] built in the composition
// root and checks every entry with the [Transport]'s CheckEndpoint and
// CheckInbound before using it.
//
// Endpoints and listener addresses in the map are IP literals: the
// controller resolves names, and nodes never ask DNS at dial time, past
// the tunnel. Transports may rely on clocks: nodes' clocks must agree
// within five minutes (udp drops datagrams sealed further than that from
// its own clock).
//
// # Traffic shape
//
// WireGuard's fixed packet sizes and its rhythm (a rekey every 2 minutes,
// keepalives) would show through any wrapper, and only the transport knows
// what traffic it imitates. So traffic shape (padding, batching, timing,
// cover traffic) is part of the transport's contract and never the layers
// above's business (PRD C6): they never pad. The contract is [Shaping],
// encoded in the map as thinkpol.transport.v1.Shaping, whose rules live in
// package internal/shaping.
//
//   - What can be asked: padding of each unit on the wire (a datagram or a
//     record) up to size buckets or by a random amount in a range
//     ([Padding]), a batching window, timing jitter, and idle cover
//     traffic. Sizes are what a capture sees.
//   - Per end: each end of a link shapes what it sends. The map's endpoint
//     carries the dialing end's shaping, its inbound link the listening
//     end's, in a shaping field next to the transport's settings; the
//     engine decodes it with [ParseShaping] and the adapter checks it.
//     Receivers undo shaping from the wire format alone, so nothing is
//     negotiated and the two ends need not agree.
//   - Refuse, never weaken: an adapter refuses a link whose shaping it
//     can't honour ([ShapingSupport], [ErrUnsupportedShaping]) rather
//     than shape less than the map asks; CheckEndpoint and CheckInbound
//     refuse it in the map, and a live link whose new shaping is refused
//     closes with [ErrSettingsRefused]. Padding and cover units sit inside
//     the transport's encryption, so they never touch its authentication
//     or replay protection.
//   - MTU: [Transport.Overhead] of a shaping is the fixed per-packet cost
//     plus the most random padding adds. Under bucket padding a packet that
//     fits the path can still round up past it, so the path layer budgets
//     WireGuard's MTU with [MaxPacket] of the transport, the shaping and
//     the largest unit the path takes.
//   - Control packets: the layers above mark the packets that only keep a
//     link warm or measure it (the path layer's probes and their replies)
//     with [WriteControl]. A [ControlWriter] may fold their rhythm into its
//     own: pad and jitter them like data, hold one up to [MaxControlHold]
//     (500 ms) to ride with data or cover, or send it as cover. WireGuard's
//     handshakes, keepalives and data never go that way. A round trip timed
//     with control packets, or through batching or jitter, is an upper
//     bound ([Shaping.MaxDelay]): liveness can rest on it, while latency
//     comparisons are made on traffic nobody holds (WireGuard's handshake
//     round trip, say).
//
// [SendStats] count what shaping costs on the wire, the overhead the lab
// weighs against what shaping hides. udp implements padding and refuses
// the rest; the lab measures how much shaping is enough per transport and
// tunes the defaults, which are no shaping until it says otherwise.
//
// # Shared listeners
//
// On a server node the supervisor owns the public address for every space
// (docs/design/server-agent.md "Server agent: one worker per space"). A transport that can
// sit behind it gives it a router ([PacketRouter], [StreamRouter]), which
// authenticates each datagram or the start of each connection and says
// which space's worker it belongs to. A [PacketRoutable] datagram
// transport opens the public socket for the supervisor (ListenPacket) and
// listens, in the worker, on what the supervisor forwards
// (ListenForwarded); a [StreamRoutable] stream transport opens the public
// listener (ListenStream) and gives the worker a [HandoffListener] for the
// connections passed to it.
//
// # Stream transports (planned)
//
// No stream transport exists yet; what follows is the design the port's
// stream side ([StreamRoutable], [StreamRouter], [HandoffListener]) is
// shaped for, and what TP-087 (`reality`, M2) and TP-028 (`tls`, after the
// MVP) build to.
//
// `tls` is TLS 1.3 with a browser fingerprint (uTLS), for node-to-node
// links. The client's auth token rides in the ClientHello, so a server
// tells its clients from probes before answering anything: probes are
// proxied whole to the real site and see its certificate. The node's own
// certificate comes from a pluggable certificate source: self-signed and
// pinned by the client first; ACME with a real domain is optional, since
// probes never see it (TP-052).
//
// `reality` is REALITY's handshake, the disguised transport for client to
// entry: a uTLS browser ClientHello whose session id seals the client's
// short id; failed authentication is spliced to a real target site. Its
// disguise is borrowed from that site: probes complete a handshake with
// the target and see its certificate, and there is no certificate of our
// own. The credential is the device's short id, a shared secret; the
// listener holds an X25519 private key. Stock VLESS clients and servers
// are not supported (TP-064's findings).
//
// Both authenticate in the ClientHello, in the legacy session id via
// uTLS. For `tls` the token is an HMAC of the credential and a coarse
// timestamp, checked by peeking at the ClientHello without terminating
// TLS, against a replay cache; for `reality` it is the short id and the
// time sealed to the listener's key, and the connection is handed over
// once its TLS session is established. An authenticated connection's file
// descriptor and the bytes already read go to the space's worker (over its
// Unix socket, package supervisor); with `tls` the worker terminates TLS
// with its own certificate, self-signed and pinned by the client. Anything
// else is proxied as a whole to the camouflage target, so a probe
// completes a handshake with the real site and sees its certificate.
//
// A replayed ClientHello takes exactly the camouflage path. A token
// already in the replay cache, one outside the timestamp window and one
// that doesn't verify are all the same thing, an unauthenticated
// connection: proxied whole to the camouflage target, with the same
// upstream connection and the same timing. A censor that captured a
// member's ClientHello and replays it learns nothing from the difference;
// dropping or resetting a replay instead would make replay an
// active-probing oracle. The token window is both the replay window (how
// long a captured ClientHello can be replayed at all, and how long the
// cache must remember a token) and the clock-skew margin (how far a
// client's clock may be off before it is locked out): a wider window means
// fewer outages and a longer replay opportunity, a narrower one the
// opposite. It starts at the five minutes nodes' clocks must already agree
// within, and the lab tunes it. The `tls` replay cache holds a token only
// for the token window, and has a bound of its own that sends a
// connection to the camouflage when reached.
//
// The camouflage target is chosen per node, not defaulted fleet-wide: one
// default shared by every node is a fingerprint of the fleet, and the
// target should be plausible for the node's address and network.
// Provisioning (TP-038) picks it, and its documentation says the choice
// is security-relevant.
//
// Server-side tells. uTLS covers the client and the camouflage site's
// certificate covers what a probe sees, but not the server's own hello: a
// worker terminating TLS with Go's stack has a JA3S/JA4S, extension order
// and ALPN that differ from the camouflage site's, a stable discriminator
// for a censor that fingerprints responses. A second tell: every probe
// makes the entry open an upstream connection to the camouflage target,
// which an ordinary server doesn't. `reality` changes less than it seems:
// a probe is spliced to the target and gets its handshake byte for byte,
// as a probe proxied by `tls` did; an authenticated session's ServerHello
// is still ours (REALITY's stack, not the target's), so the first tell
// remains for a censor that compares members' sessions with the site's;
// and every failed probe still dials the target, the same upstream tell as
// `tls`'s proxying. What it removes is a certificate of our own to manage.
// The lab's prober measures both tells (TP-026, TP-032), for `reality`
// too, and the matrix shows them.
package transport
