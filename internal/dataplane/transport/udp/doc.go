// Package udp is the baseline transport: one datagram per packet, sealed
// with keys derived from the link secret. WireGuard's headers never appear on
// the wire (C1), but timing shows through untouched, packet sizes do unless
// the link pads, and a link's datagrams all start with the same connection
// id for an hour: this is the transport the censor lab is supposed to catch.
//
// # Wire format
//
//	conn id [8] | nonce [24] | XChaCha20-Poly1305(sender [12] | sent [4] | counter [8] | frames | padding)
//	frame: length [2] | packet [length]
//
// The connection id is HKDF-SHA256 of the link secret, the direction and the
// hour (Unix time / 3600), in clear and authenticated as the AEAD's
// associated data; receivers accept the ids of the current hour and the two
// next to it. It tells a shared listener which credential to check, and it
// changes hourly so a link isn't one constant tag forever. Rotation doesn't
// unlink anything an observer can link by addresses and ports: a link's
// datagrams share their 5-tuple across the change. Each direction of
// a credential has one key (HKDF-SHA256 of the link's credential) and every
// datagram a fresh random 192-bit nonce: no session, epoch or nonce counter
// exists that a restart, a redial or a table change could reuse.
//
// The seal is an AEAD, XChaCha20-Poly1305, under a symmetric key both ends
// of the link derive, which authenticates every datagram; not a NaCl
// sealed box, which is only for what is sealed to a public key (such as the
// map's sections).
//
// Inside the seal: the sender (its creation time in nanoseconds, strictly
// increasing per process, and 4 random bytes; a new one per dial and per
// listener-side link), the time the datagram was sent (Unix seconds, a
// uint32 that wraps in 2106; the freshness check allows for it), a
// counter per sender, and the packets, each behind its length. A zero
// length, or fewer than two bytes left, ends the packets; the rest is
// padding, zeros sealed with everything else. A sender puts one packet in
// each datagram today. Receivers take any number, none included (a cover
// datagram: it passes every check below and keeps the link's address
// current, but opens no link), so batching and cover traffic can come
// later without changing what receivers accept.
//
// # Shaping
//
// Each end pads what it sends as its transport.Shaping says (the dialer's
// DialConfig, the listener's PeerLink), to buckets or at random (at most
// MaxRandomPadding bytes); bucket sizes are datagram sizes, up to 8778
// bytes. Padding sits inside the AEAD: it is authenticated and its length
// is visible only as the datagram's. The receiver needs no setting to undo
// it, and a table change re-pads a live link's next reply. udp refuses
// batching, timing jitter and cover traffic (transport.ErrUnsupportedShaping)
// rather than ignore them. Overhead is 74 bytes, plus the largest random
// padding; transport.MaxPacket gives the MTU budget under buckets. A table
// change to shaping udp refuses closes the live link with
// transport.ErrSettingsRefused.
//
// # What a receiver accepts
//
// A datagram is delivered only if it authenticates under a credential in
// the table, was sent within five minutes of the receiver's clock, and
// passes the sender rules:
//
//   - each of the last 8 senders of a credential has a sliding replay
//     window of 1984 counters (a bitmap ring, as in RFC 6479); a counter
//     is accepted once, and not if it is that far or further behind the
//     newest;
//   - an unknown sender older than the current one is dropped, unless the
//     current one has been silent for 30 seconds (a dialer whose clock went
//     back); a refused sender keeps its slot, with its counters recorded,
//     so showing its datagrams again later is a replay;
//   - a sender evicted from the slots, or a credential taken out of the
//     table, is remembered by id for as long as a datagram of it could
//     still be fresh, together with the newest sealed send time seen from
//     it: a sender it keeps turning away refreshes that time with every
//     datagram, so the memory runs out no sooner than the freshness check
//     would — on the sealed send time, not on the receiver's clock alone,
//     which a step of NTP could move — and past the memory a replay would
//     come back as a "new" sender. A credential's evicted senders are at
//     most 1024, the oldest forgotten first, so a dialer churning through
//     senders can't make this grow, or cost more per datagram, without
//     bound. A credential taken out of the table keeps its whole sender
//     history (its slots and its evicted ids) until its newest sealed send
//     time is no longer fresh, so taking it out and putting it back
//     doesn't reopen it to replays;
//   - only the current sender's newest counter opens a link or moves a
//     link's reply address; an older counter of the current sender is
//     delivered on an open link and dropped otherwise.
//
// Everything else goes to the camouflage, and is counted: stale timestamps
// apart from the rest, so a clock that is off is easy to spot, and
// datagrams no link could take apart from theirs. Nodes' clocks must agree
// within five minutes.
//
// The guarantee: a datagram's sealed send time is dead everywhere five
// minutes after it — up to ten minutes after it was sent, if the sender's
// clock was a full skew ahead — and within one listener's lifetime a
// datagram it has seen, or a sender it has seen, never delivers twice or
// moves a link. What remains:
//   - the receiver's memory is per process. A listener restarted behind a
//     Router that keeps running (a server's worker under its supervisor)
//     loses nothing: the Router still drops the replays. Where the memory
//     goes with the process that holds the WireGuard devices too (a
//     supervisor restart, whose workers die with it, or a node in device
//     mode restarting), a replay of datagrams sent in the last ten minutes
//     (five, if the sender's clock was right) opens a link (to the
//     replayer's address, until the real dialer's next datagram moves it
//     back) and delivers each of their packets once more, to a fresh
//     WireGuard device that answers a replayed handshake initiation
//     (RESIDUAL-RISKS.md RR34; TP-069);
//   - an on-path attacker can hold back the newest datagram the listener
//     never saw and show it later: ahead of the original, or, from an
//     older sender, once the current sender has been quiet for 30 seconds
//     (that is what a dialer whose clock went back looks like); with no
//     link open it opens one toward the attacker's address, which lasts
//     until DeadAfter; as with WireGuard's own roaming, it moves the link
//     until the real dialer's next datagram;
//   - a sender evicted from the slots and then pushed out of the evicted
//     ids by more than 1024 further evictions while its datagrams could
//     still be fresh is forgotten: it can take over again once the current
//     sender has been silent for 30 seconds. Making those evictions takes
//     the credential.
//
// # Links
//
// There is no handshake: a link opens at the listener with the first
// datagram of its credential whose sender's newest counter it is, a redial
// carries on the same link, and a dialer's link carries on with a listener
// restarted on the same address. A link the app closed — a probe timeout,
// a table change, whatever the path layer's reason — reopens the same way
// at once if the dialer is still sending, and a reordered datagram of a
// sender already seen opens nothing toward the port it came from.
//
// A server node's supervisor shares one public socket between spaces: the
// transport's Router finds each datagram's credential by connection id,
// authenticates it (tag and timestamp) and filters replays per credential,
// then names its space; the supervisor forwards it as is to that space's
// worker, whose Listener ([Transport.ListenForwarded] over a net.PacketConn
// fed by the supervisor) decrypts and filters again. So a replay, which
// anyone with a passive tap can send, never reaches a worker or costs its
// space anything while that supervisor runs. The supervisor keeps one
// Router per transport, for all its sockets and across their reopens, so a
// datagram replayed to another listener is still a replay. A new Router (a supervisor restart)
// routes replays of the last ten minutes (five, if the sender's clock was
// right) once more; the worker's Listener, if it kept running, would
// still drop them, but workers die with the supervisor, so today they are
// delivered and answered (not yet handled; see TP-069).
package udp
