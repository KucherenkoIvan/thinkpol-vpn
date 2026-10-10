// Package udp is the baseline transport: one datagram per packet, sealed
// with keys derived from the link secret. WireGuard's headers never appear on
// the wire (C1), but packet sizes and timing show through untouched, and a
// link's datagrams all start with the same connection id for an hour: this
// is the transport the censor lab is supposed to catch.
//
// # Wire format
//
//	conn id [8] | nonce [24] | XChaCha20-Poly1305(sender [12] | sent [4] | counter [8] | packet)
//
// The connection id is HKDF-SHA256 of the link secret, the direction and the
// hour (Unix time / 3600), in clear and authenticated as the AEAD's
// associated data; receivers accept the ids of the current hour and the two
// next to it. It tells a shared listener which credential to check, and it
// changes hourly so a link isn't one constant tag forever. Rotation doesn't
// unlink anything an observer can link by addresses and ports: a link's
// datagrams share their 5-tuple across the change. Each direction of
// a credential has one key (HKDF-SHA256) and every datagram a fresh random
// 192-bit nonce: no session, epoch or nonce counter exists that a restart, a
// redial or a table change could reuse.
//
// Inside the seal: the sender (its creation time in nanoseconds, strictly
// increasing per process, and 4 random bytes; a new one per dial and per
// listener-side link), the time the datagram was sent (Unix seconds), and a
// counter per sender.
//
// # What a receiver accepts
//
// A datagram is delivered only if it authenticates under a credential in
// the table, was sent within five minutes of the receiver's clock, and
// passes the sender rules:
//
//   - each of the last 8 senders has a sliding replay window; a counter is
//     accepted once, and not if it is too far behind the newest;
//   - an unknown sender older than the current one is dropped, unless the
//     current one has been silent for 30 seconds (a dialer whose clock went
//     back); a refused sender keeps its slot, with its counters recorded,
//     so showing its datagrams again later is a replay;
//   - a sender evicted from the slots is refused for five minutes, after
//     which its datagrams are stale anyway; a credential taken out of the
//     table keeps its senders for as long, should it come back;
//   - only the current sender's newest counter moves the link's reply
//     address.
//
// Everything else goes to the camouflage, and is counted: stale timestamps
// apart from the rest, so a clock that is off is easy to spot. Nodes'
// clocks must agree within five minutes.
//
// The guarantee: a datagram captured more than five minutes ago is dead
// everywhere, and within one listener's lifetime a datagram it has seen,
// or a sender it has seen, never delivers twice or moves a link. What
// remains:
//   - the receiver's memory is per process: after a listener restart, a
//     replay of datagrams sent in the last five minutes opens a link (to
//     the replayer's address, until the real dialer's next datagram moves
//     it back) and delivers each of their packets once more; WireGuard
//     drops them;
//   - an on-path attacker can hold back a datagram the listener never saw
//     and show it later: ahead of the original, or, from an older sender,
//     once the current sender has been quiet for 30 seconds (that is what
//     a dialer whose clock went back looks like); as with WireGuard's own
//     roaming, it moves the link until the real dialer's next datagram.
//
// # Links
//
// There is no handshake: a link opens at the listener with the first
// datagram of its credential, a redial carries on the same link, and a
// dialer's link carries on with a listener restarted on the same address.
//
// A server node's supervisor shares one public socket between spaces: the
// transport's Router finds each datagram's credential by connection id,
// authenticates it (tag and timestamp) and names its space; the supervisor
// forwards it as is to that space's worker, whose Listener
// (Transport.ListenOn over a net.PacketConn fed by the supervisor) does the
// rest. The Router keeps no replay state, so it forwards replays of the last
// five minutes; the worker drops them.
package udp
