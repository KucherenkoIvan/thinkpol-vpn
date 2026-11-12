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
// (Options.Now), not before the second the listener started in (udp's
// start rule, transport.StartRule: its replay memory starts empty), and
// wasn't seen before.
//
// Without an Admission.Camouflage, what fails is spliced to the target, raw
// and whole, so a prober completes a handshake with the real site and sees
// its certificate; the timing is the site's too. As REALITY's own server
// does, the listener dials the target when it accepts a connection, before
// reading anything, and passes each chunk of the hello on as it arrives:
// whatever the target answers, and its closing, reach the client as they
// happen, so a prober that stalls is closed when the site would close it.
// Only the last byte of a whole hello waits until the listener decided:
// on a hello that fails it follows at once; on one that authenticates
// REALITY sends it under its own lock, so the target can't answer before
// REALITY took the connection (a target answering first would have its
// real ServerHello spliced to the authenticated client).
//
// A target that can't be reached closes the connection. The target's FIN,
// even before it sent anything, reaches the client as a half-close and
// what the client still sends goes on to the target, as the site's own
// lingering close reads on: a prober still sending gets the site's FIN,
// not a reset, where REALITY's server closes both (a difference the lab's
// prober caught under load). The client's FIN before its hello was whole
// closes both. Once spliced, each side's FIN is passed on as a
// half-close, and the other direction ends once it was idle for 5 s,
// which REALITY's server doesn't do (a client that stays silent after the
// site closed would hold both connections for good; an answer that keeps
// flowing isn't cut). Closing
// the listener ends its splices, cancels its dials to the target and
// waits for both. With an Admission.Camouflage, the hello is read whole
// (for at most 10 s) before anything is dialled, and what fails goes to
// the camouflage.
//
// A listener bounds what it holds before and instead of a link, each
// connection costing it two descriptors (the client's and the target's):
// at most 1024 connections whose hello is being decided (from before the
// target is dialled until the decision) and, apart from those, at most
// 1024 spliced to the target, for as long as the target keeps each open.
// Past either, a new connection is closed, as an overloaded site would
// close it. Kept apart, strangers holding splices open through the site
// (an HTTP keep-alive a minute) close only other strangers, never a
// member's hello; what still starves members is a sustained flood of new
// connections each sending nothing until the deadline of whoever routes
// it (RESIDUAL-RISKS.md RR38).
//
// Replays are remembered by sealed session id while their sealed time is
// in the window, in memory per listener, so the start rule above is what
// refuses a capture replayed after a restart (what it still lets in is
// RESIDUAL-RISKS.md RR34's). The memory is a cache per space: within a
// space each short id has a share of at most 1024 at once and the cache
// at most 65536 (past either, a new hello is spliced too), so a
// credential dialling faster than any device would fills its own share
// only, and a space's map listing enough credentials to fill its cache
// refuses its own hellos, never another space's, and learns nothing of
// another space's traffic. Each entry is forgotten when its own sealed
// time leaves the window; a space's cache once it left the table and
// remembers nothing fresh. A replayed hello is spliced like any failed
// authentication.
//
// Two peer links sharing a short id are both rejected, not one guessed,
// with one exception for links of different spaces (a shared listener's
// merged table): one that was in the table before, alone in its space,
// stays and only the newcomers are rejected, so one space's map can't
// knock out another's link by listing its short id. With neither in the
// table before (both new, or a fresh start), both are rejected.
//
// The listener takes a table change in a goroutine of its own. Until it
// has, a short id the change added fails authentication like any other:
// spliced to the target (or given to the camouflage), so the client's
// REALITY handshake fails and it dials again. A short id the change removed
// between a hello's authentication and its admission is checked again at
// admission, so its connection closes instead of becoming a link.
//
// An authenticated connection's TLS handshake is REALITY's server
// (github.com/xtls/reality, an unmodified MPL-2.0 module dependency, see
// TP-087's Notes), given the ClientHello again and the target connection
// dialled at accept, which has all of the hello but its last byte
// (REALITY forwards the hello again; all of it but that byte is dropped):
// it imitates the target's ServerHello
// and post-handshake records, and answers with a certificate of its own,
// an Ed25519 key whose signature is HMAC-SHA512(auth key, public key), the
// auth key being the seal's key. It checks the seal again, with its time
// on the real clock, not Options.Now, and splices what it refuses to the
// target itself, whatever the Admission.Camouflage. Its handshake is
// bounded (15 s) once the hello authenticated; that bound stays on a
// connection REALITY refuses and splices, so a legitimate hello at the
// window's edge that REALITY refuses is cut after 15 s (known).
//
// Listen first completes a TLS 1.3 handshake with the target for each
// server name, through Control, within 10 s, and fails, naming the target
// and the reason, unless the target's certificate verifies against the
// system roots: REALITY's detection of the target's records stores the
// same empty result for a certificate it can't verify as for a site that
// sends no records, and the target would be imitated without them. A
// target that doesn't speak TLS 1.3 fails too, the error saying so:
// REALITY imitates only a TLS 1.3 ServerHello, so every authenticated
// handshake would fail.
// Options.TrustTargetRoots replaces the system roots for tests and the lab
// only; REALITY's detection still uses the system roots, so a target
// trusted that way is imitated without post-handshake records.
//
// Then Listen has REALITY learn the target's post-handshake records and
// waits for that, up to 10 s; REALITY dials the target for that without
// the Control hook. Listen fails if REALITY's detection didn't end (the
// target stalled): REALITY keeps what it learned per process, and would
// otherwise hold every authenticated handshake for good. REALITY's
// detection runs on after Listen gave up on it, with no deadline, and
// would store an empty result over a later detection's pending one, so
// detections of a target are serialized: a later Listen fails while the
// earlier detection still runs, then forgets every result it left and
// detects again. A result isn't that detection's last write (having
// stored the records it read, it closes its connection, then checks the
// key once more), so a result it left is forgotten only once it has stood
// for a second. A detection whose target accepted the connection and then
// stays silent never ends: its keys stay pending, and every later Listen
// for that target fails until the process restarts. A caller retrying
// Listen should know that a failure naming an earlier detection won't
// clear on retry while the target stays silent.
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
// A shaping that asks for no padding pads every record to at least
// MinRecord (512) bytes, a product default the lab set (TP-201): unpadded,
// a rekey's two records showed in the handshake size band the lab's
// wireguard-rhythm censor watches, and it caught reality within two rekey
// periods. The cost is up to 488 bytes on each small record (a TCP ACK
// through the tunnel, a ping); a full record is unchanged. A map that
// pads to buckets or at random gets what it asks for instead; it can't
// ask for no padding at all. What the floor still shows (the rekeys'
// timing, and the floor itself) is RESIDUAL-RISKS.md RR58.
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
// # Behind a shared listener
//
// On a server node the supervisor owns the public address
// (transport.StreamRoutable). One StreamRouter serves every reality
// listener of the supervisor, over the merged table of every space
// served: it holds the table and the replay cache (per space, remembered
// for five minutes whatever each listener's window) and the start rule,
// taken when it was made. ListenStream binds a public listener to it
// (another transport's router is an error), after the same checks as
// Listen (the target's certificate, then REALITY's detection of its
// records), and reads what REALITY learned of the records out of its
// per-process store into the listener's handoff settings (its settings
// and the records, JSON: the supervisor and its workers are one binary).
//
// The public listener's RouteStream decides each connection exactly as a
// standalone listener does up to the decision, with the same code (a
// gate, its bounds included): the target dialled at accept, the hello
// mirrored to it but its last byte, the seal opened with the listener's
// key, the short id found in the merged table, its space served (the
// supervisor's callback), the time within the listener's window and not
// before the router's start, the hello admitted once in its space's
// cache. It calls waiting once the mirror is up: from then on the
// connection only waits for its dialer, under the listener's bounds,
// and the supervisor's bound on routing work lets go of it. What fails
// is spliced to the target there, and the verdict says why (unknown, a
// space not served, stale, replayed), the space included where the hello
// authenticated. The supervisor's routing deadline (10 s) passing before
// the hello was whole ends the routing, not the connection: it stays
// spliced to the target, whose own timeouts end it, as a standalone
// listener's would. The listener's Camouflage, where the supervisor
// sends what it turns away before routing, is the same splice to the
// target, under the same splice bound. What authenticates is handed over
// with the target connection, which has all of the hello but its last
// byte, and anything the target sent before the mirror stopped (the
// supervisor passes both descriptors to the space's worker).
//
// The worker's Handoff first puts the records from the handoff settings
// into its own process's store, where REALITY's server reads them: the
// worker's sandbox has no CA bundle, so REALITY's detection there could
// never verify the target, and a guest space's worker can't reach the
// node owner's target at all. Then each connection is served as a
// standalone listener serves one that authenticated: the seal opened
// again and the short id looked up in the worker's own table (not the
// replay cache or the start rule: the router admitted the hello once),
// and REALITY's handshake run on the handed-over target connection (it
// never dials). A hello the worker's table doesn't list (its map changed
// in between) is spliced to the target, the held-back byte sent then.
// Every worker given the listener's handoff settings holds its private
// key, which REALITY's server needs (RESIDUAL-RISKS.md RR57).
package reality
