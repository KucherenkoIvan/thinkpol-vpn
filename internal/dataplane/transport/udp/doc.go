// Package udp is the baseline transport: one datagram per packet, obfuscated
// and authenticated with keys derived from the link secret. WireGuard's
// headers never appear on the wire (C1), but packet sizes and timing show
// through untouched and every datagram of a link starts with the same
// connection id: this is the transport the censor lab is supposed to catch.
//
// Each datagram carries a keyed connection id, the dialer's session and a
// counter in clear, then the packet sealed with AES-256-GCM under a key per
// session and direction (HKDF-SHA256 from the secret); the clear header is
// authenticated too. The listener drops replays with a sliding window per
// session, and refuses a session older than the newest it has seen from the
// same credential, unless that one has gone quiet for three minutes (a
// dialer whose clock went back). There is no handshake: a link opens at the
// listener with its first datagram, and a dialer that redials starts a new
// session, which supersedes the old link.
//
// A server node's supervisor shares one public socket between spaces: it
// routes each datagram by connection id with a Demux and forwards it as is
// to the worker of the space it belongs to, whose Listener (NewListener over
// a net.PacketConn fed by the supervisor) does the rest.
package udp
