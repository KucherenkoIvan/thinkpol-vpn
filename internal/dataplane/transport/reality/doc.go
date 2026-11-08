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
// transport.MaxClockSkew, never more) on the listener's clock
// (Options.Now) and wasn't seen before.
//
// Without an Admission.Camouflage, what fails is spliced to the target, raw
// and whole, so a prober completes a handshake with the real site and sees
// its certificate; the timing is the site's too. As REALITY's own server
// does, the listener dials the target when it accepts a connection, before
// reading anything, and passes each chunk of the hello on as it arrives:
// whatever the target answers, and its closing, reach the client as they
// happen, so a prober that stalls is closed when the site would close it.
// A target that can't be reached closes the connection. Once one direction
// of a splice ended cleanly, the other gets 5 more seconds (a client that
// stays silent after the site closed would hold both connections for
// good), and closing the listener ends its splices. With an
// Admission.Camouflage, the hello is read whole (for at most 10 s) before
// anything is dialled, and what fails goes to the camouflage.
//
// Replays are remembered by sealed session id while their sealed time is
// in the window, in memory per listener (a capture replayed after a
// restart, within its window, is authenticated again). Each short id has a
// share of at most 1024 at once, the cache at most 65536 (past either, a
// new hello is spliced too), so a credential dialling faster than any
// device would fills its own share only; each entry is forgotten when its
// own sealed time leaves the window. A replayed hello is spliced like any
// failed authentication.
//
// An authenticated connection's TLS handshake is REALITY's server
// (github.com/xtls/reality, an unmodified MPL-2.0 module dependency, see
// TP-087's Notes), given the ClientHello again and the target connection
// dialled at accept, which already has the hello (REALITY forwards it
// again; those bytes are dropped): it imitates the target's ServerHello
// and post-handshake records, and answers with a certificate of its own,
// an Ed25519 key whose signature is HMAC-SHA512(auth key, public key), the
// auth key being the seal's key. It checks the seal again, with its time
// on the real clock, not Options.Now, and splices what it refuses to the
// target itself, whatever the Admission.Camouflage. Its handshake is
// bounded (15 s) once the hello authenticated; that bound stays on a
// connection REALITY refuses and splices, so a legitimate hello at the
// window's edge that REALITY refuses is cut after 15 s (known).
//
// Listen first has REALITY learn the target's post-handshake records and
// waits for that, up to 10 s; REALITY dials the target for that without
// the Control hook. Listen fails if it didn't learn them (the target can't
// be reached, doesn't complete a handshake, or stalls): REALITY keeps what
// it learned per process, and would otherwise imitate no records or hold
// every authenticated handshake for good.
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
