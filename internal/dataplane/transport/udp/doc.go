// Package udp is the baseline transport: one datagram per packet, sealed
// with keys derived from the link secret. WireGuard's headers never appear on
// the wire (C1), but packet sizes and timing show through untouched and every
// datagram of a link starts with the same connection id: this is the
// transport the censor lab is supposed to catch.
//
// It is deliberately stateless where crypto is concerned. WireGuard inside
// already provides confidentiality, integrity, replay protection and
// roaming; this layer only hides WireGuard's headers, authenticates the
// credential so a shared listener can route datagrams, and drops junk
// cheaply. So each datagram is sealed with XChaCha20-Poly1305 under a fixed
// key per credential and direction (HKDF-SHA256 from the secret) and a fresh
// random 192-bit nonce: there is no session, epoch or nonce counter that a
// restart, a redial or a table change could reuse. A keyed connection id in
// clear (the AEAD's associated data) names the credential.
//
// Inside the seal, a random sender id per link end and a counter feed a
// sliding replay window per sender (the last few senders are remembered).
// It is a pre-filter, not a guarantee: a restart forgets it, and a replay of
// a forgotten sender passes once more, to be dropped by WireGuard. A link
// follows its dialer's address, but only on the newest counter of a sender;
// an on-path attacker can still race a captured datagram ahead of the
// original, as with WireGuard's own roaming.
//
// There is no handshake: a link opens at the listener with the first
// datagram of its credential, a redial carries on the same link, and a
// dialer's link carries on with a listener restarted on the same address.
//
// A server node's supervisor shares one public socket between spaces: it
// routes each datagram by connection id with a Demux and forwards it as is
// to the worker of the space it belongs to, whose Listener (NewListener over
// a net.PacketConn fed by the supervisor) does the rest.
package udp
