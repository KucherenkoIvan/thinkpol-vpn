// Package reality is the disguised transport for client → entry links: it
// speaks REALITY's handshake, so a listener borrows a real site's TLS (the
// target) and anyone without a valid short id is spliced to that site
// (docs/design/transports.md "Transports"). Links are TCP; packets travel
// as frames inside TLS 1.3 records.
//
// # The handshake
//
// The dialer sends a Chrome ClientHello (uTLS, HelloChrome_Auto) whose
// 32-byte session id is a seal:
//
//	session id = AES-256-GCM(key, nonce = Random[20:32],
//	    version [3] | 0 | Unix seconds [4] | short id [8],
//	    additional data = the ClientHello handshake message, session id zeroed)
//	key = HKDF-SHA256(X25519(client share, listener key), salt = Random[:20], info "REALITY")
//
// The client share is the hello's standalone X25519 share, else the X25519
// half of its X25519MLKEM768 share; a hello without X25519MLKEM768 before
// its X25519 share is refused, as REALITY's server refuses it. The short id
// (8 bytes, the link's credential and verifier) is a shared secret.
//
// The listener reads the first TLS record before answering anything. It
// must be one ClientHello for one of the listener's server names, offering
// TLS 1.3, whose seal opens under the listener's key, names a short id in
// the table, was sealed within the time window (five minutes by default,
// transport.MaxClockSkew, never more) and wasn't seen before. Anything
// else goes to the camouflage with the bytes already read: without an
// Admission.Camouflage, that is the splice to the target, raw and whole,
// so a prober completes a handshake with the real site and sees its
// certificate. A target that can't be reached closes the connection.
// Replays are remembered by sealed session id while their sealed time is
// in the window (at most 65536 at once; past that, a new hello is spliced
// too), so a replayed hello is spliced like any failed authentication.
//
// An authenticated connection's TLS handshake is REALITY's server
// (github.com/xtls/reality, an unmodified MPL-2.0 module dependency, see
// TP-087's Notes), given the ClientHello again: it dials the target,
// imitates its ServerHello and post-handshake records, and answers with a
// certificate of its own, an Ed25519 key whose signature is
// HMAC-SHA512(auth key, public key), the auth key being the seal's key. It
// checks the seal again and splices what it refuses. Its handshake is
// bounded (15 s) once the hello authenticated. Listen first has REALITY
// learn the target's post-handshake records and waits for that, up to
// 10 s; REALITY dials the target for that without the Control hook.
//
// The dialer checks the certificate the same way. Anything else (a real
// certificate: the connection was spliced, or a man in the middle
// answered) fails the dial with ErrNotAuthenticated, but only after the
// handshake completes, as a browser's unused preconnect would end, rather
// than with an alert no browser sends to a valid site.
//
// What REALITY's own server still tells a censor (the upstream dial on
// every connection, its ServerHello against the target's) is RR31's.
//
// # Frames
//
// Each packet is one write, so one TLS record, holding a packet frame and,
// when shaping pads it, a padding frame:
//
//	packet:  length [2] (1 to 8192, top bit clear) | packet
//	padding: 0b11 | length [14 bits] | zeros [length]   or   0x80 (one byte)
//
// The receiver reads frames off the stream, never needing record
// boundaries, so it undoes padding from the wire alone. Dynamic record
// sizing is off at both ends, so a record's size is what shaping made it.
//
// # Shaping
//
// Each end pads its records as its transport.Shaping says: to buckets
// (record sizes, header and tag included, up to 16406 bytes, one full
// record) or at random (at most MaxRandomPadding bytes). Batching, jitter
// and cover traffic are refused (transport.ErrUnsupportedShaping). Overhead
// is 24 bytes per packet (record header, inner content type, AEAD tag and
// frame length), plus the largest random padding.
//
// # Settings
//
// The listener's settings are a RealityListenSettings (X25519 private key,
// target IP:port, server names, time window); a dialer's a
// RealityDialSettings (server name, the listener's public key,
// fingerprint: only "chrome" so far); a peer link's a
// RealityInboundSettings, empty. The target is an IP literal: nodes never
// resolve names.
//
// # Not yet
//
// reality doesn't sit behind a server node's shared listener yet (no
// transport.StreamRoutable): the short id selecting the space, and the
// handoff of the connection to the space's worker, are TP-201.
package reality
