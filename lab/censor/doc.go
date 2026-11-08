// Package censor is the lab's pluggable censor (PRD C4; docs/design/lab.md
// "Censor lab"): a program in the lab router's container, censord, that
// nftables hands every forwarded packet to through an NFQUEUE, and that
// decides each packet's fate with switchable modules.
//
// # The program
//
// censord runs in the lab router's container. Its nftables table sends
// every forwarded packet, IPv4 and IPv6, whole, to an NFQUEUE, served with
// florianl/go-nfqueue (pure Go); the NFQUEUE glue is in queue_linux.go, and
// the censor never runs anywhere but inside a lab router. The [Engine]
// decides each packet with the modules the test picked in the JSON [Config]
// censord starts with ([Build]: a module name nobody registered is an
// error, since a test asking for a censor that doesn't exist must not
// silently censor less), and writes what it decided to a verdict log the
// tests read (see "The verdict log").
//
// # Flows and streams
//
// A [Flow] is one direction of a connection ([FlowKey]); the engine links
// it to the other direction once it sees a reply ([Flow.Reverse]), so a
// module reading a server's hello finds the client's (JA3S, TP-026).
//
// A TCP flow carries a [Stream]: the sender's bytes in order as a Linux
// receiver reads them, reassembled from segments that arrive out of order,
// overlap or repeat, with wrapping sequence numbers. Where copies of the
// same bytes differ, the stream keeps the one Linux keeps: an in-order
// segment's bytes beat any copy waiting out of order, and among those
// waiting Linux's out-of-order queue rules (the copy starting first wins;
// at one offset the first copy, unless a later one reaches further and
// replaces it; neighbours merge, so a copy starting at their joint loses
// to them). A segment's payload Linux discards never enters the stream: a
// bad TCP checksum, data without ACK, data on an RST, data on a SYN (lab
// servers don't enable TCP Fast Open), and a segment starting more than 32
// MiB past the next byte to read, further than any window a lab receiver
// advertises with Linux's default buffers (6 MiB at most). The queue hands packets over with full checksums (without
// NFQA_CFG_F_GSO the kernel completes an offloaded one first), so checking
// them is sound. The verdict log names each reason a flow kept payload out
// once ([EventIgnore]), and the flow's summary counts them.
//
// The stream keeps its first 16 KiB as a prefix (a ClientHello split over
// two segments is one prefix once the second arrives) and, for each
// packet, the bytes it made readable in order ([Stream.Fresh]), past the
// prefix too, so a module can follow a whole stream over time (TLS record
// sizes, say) while the censor keeps only the prefix. Out-of-order bytes
// wait in at most 16 KiB; past that the farthest are dropped
// ([Stream.Broken]), so junk sent far ahead never displaces the bytes
// next to be read. A UDP flow keeps its first datagram with a good
// checksum instead. That retained payload ([Flow.Payload]) is what active
// modules get to replay. Flows also carry what a flow-level classifier
// times: when the flow started, its latest packet, its packet and byte
// counts.
//
// A flow starts over, everything about it forgotten (stream, verdicts,
// retired modules, tags, a flag not yet applied), when its addresses and ports carry a new
// connection, so a new connection is read and judged from its own first
// byte: TCP once a SYN with a new sequence number is accepted by the
// SYN-ACK acknowledging it, both directions at once (a SYN alone restarts
// nothing, since a receiver with the connection open ignores it, so it
// can't shake off a pinned verdict); UDP after 120 s without a packet in
// either direction, Linux conntrack's timeout for a UDP flow with
// replies, also both directions at once. The old flows' summaries are
// logged then.
//
// # Modules
//
// Modules register from init ([RegisterPassive], [RegisterActive]), like
// cmd/thinkpol's commands, and are passive, active or both:
//
//   - [Passive]: shown packets in config order and returning a [Decision]:
//     accept, drop, reset or throttle, optionally pinned to the flow, and
//     optionally a tag that hands the flow to the active modules as
//     suspect. Reset drops the packet and sends RSTs the censor builds
//     itself, from raw sockets: one to the packet's sender with a sequence
//     number it believes, and, when the packet carries an ACK (the
//     receiver has a connection to break), one to its receiver at the
//     dropped packet's sequence number, the one RST a receiver acts on at
//     once; a reset SYN-ACK's receiver, still in SYN-SENT, gets RST|ACK
//     acknowledging its SYN instead, the only RST it takes. It is TCP's
//     only; on any other protocol the engine drops instead. Throttle is a
//     policer of the connection: a token bucket per direction at the
//     decision's rate (about 14 kbit/s unless the module says otherwise)
//     accepts or drops each packet with payload at once; nothing is held,
//     and a packet without payload always passes. Once a packet of a flow
//     is throttled, its reverse is pinned to the same throttle, so a
//     module that matches one direction (block-ip by destination) slows
//     the replies too. A flow's bucket keeps the rate of the first
//     throttle applied to it.
//   - [Active]: acting on their own (the prober, TP-026). They are fed a
//     snapshot of each new flow the censor sees and of each flow a passive
//     module tags, with its retained payload, and may probe and flag flows
//     ([FlagFunc]); a flag is pinned from the flow's next packet on.
//     Feeding them never makes the queue wait: a snapshot an active module
//     has no room for is counted ([Engine.Unnoticed]) and skipped.
//   - both: a module built by [RegisterPassive] that also implements
//     [Active] is run as both, one value, so its passive half can tag what
//     its active half acts on.
//
// Verdicts compose by one rule: only Drop and Reset end the module walk.
// A flow pinned to Drop or Reset is decided before any module looks.
// Otherwise every passive module that hasn't retired from the flow sees
// the packet, in config order: the first Drop or Reset decides it; with
// none, a Throttle does (the flow's pinned one, else the first module's to
// give one); else Accept. A module that pins a verdict retires from the
// flow, whatever the verdict, and the modules after it, and active
// modules' flags, may still block it: a Throttle, pinned or not, never
// keeps a later module from dropping or resetting the flow. A flow's
// pinned verdict only ever gives way to a more severe one (drop and reset
// over throttle), so a flag never lifts a block and an Accept flag changes
// nothing.
//
// New modules join by registering themselves. Two modules prove the
// framework, and are not censors of their own: block-ip decides packets by
// destination (optionally only those with payload, so a handshake completes
// first; the matrix's address blocklist is ip-blocklist), and replay,
// passive and active at once, tags a TCP flow to its destinations once its
// stream holds a whole TLS record and replays the retained bytes to the
// flow's destination from the router.
//
// The blocklists and the VPN fingerprints are what real censors block
// first (docs/design/lab.md "Censor lab"), each pinning its verdict to the
// flows it blocks and retiring from the flows it has judged otherwise:
//
//   - ip-blocklist blocks every packet to or from a listed address or
//     network, either end of a connection, both families (drop by
//     default). A list of any length costs one map lookup per prefix
//     length it uses.
//   - sni-blocklist blocks a TCP connection whose ClientHello asks for a
//     listed name or a name under one (reset by default). It reads the
//     ClientHello from the stream, so one split over segments, out of
//     order, or over TLS records is read whole; its packets pass until
//     it is, and the packet that completes it meets the verdict. A stream
//     that starts otherwise, is joined midstream, or whose ClientHello
//     outgrows the prefix is not judged; a ClientHello without a name
//     passes, and so does ECH's inner name, which it can't read.
//   - wireguard-fingerprint blocks a UDP flow on its first datagram that
//     looks like a WireGuard message, on any port: a type from 1 to 4
//     and three zero bytes, at the type's size (148-byte initiations,
//     92-byte responses, 64-byte cookie replies, transport data of 32
//     bytes or more; drop by default). Transport data alone matches,
//     full-MTU packets the kernel can't pad to 16 bytes included, so a
//     tunnel up before the censor is caught by its next packet. Random
//     bytes match the header about once in a billion datagrams, but
//     structured UDP does not: an iterative DNS query (flags 0x0000) with
//     query ID 0x0400 starts with 04 00 00 00 and is 32 bytes or more,
//     about 1 in 65,536 such queries, and the flow's drop is pinned.
//     thinkpol's udp transport carries WireGuard, but nothing on its
//     wire looks like it (PRD C1, lab TestM0), so it passes.
//   - openvpn-fingerprint blocks an OpenVPN connection, over UDP or TCP
//     (each packet behind its length), on any port, by its handshake's
//     opcodes (Xue et al., USENIX Security 2022): the client's first
//     packet a hard reset (opcode 7, or 10 with tls-crypt-v2), the
//     server's first its answer (8), the client's next a control or ack
//     packet (4, 5 or 11) with its reset's session id, all of key id 0.
//     The client's second packet and the connection after it, both ways,
//     meet the verdict (drop by default). tls-auth and tls-crypt leave
//     these bytes in the clear; a connection past its handshake when the
//     censor started passes, and so does one that strays from the
//     pattern (an obfuscating patch, a static key).
//
// wireguard-rhythm is a censor of its own, one of the M2 gate's checks
// (docs/design/milestones.md): it frames each TCP stream's TLS records and
// blocks a connection, both ways, whose application-data records show
// WireGuard's rhythm. It reads recurrence, not WireGuard's exact sizes, so
// padding to small buckets or a different overhead each way doesn't hide
// it. Two signals each show the rhythm:
//
//   - rekey: an exchange, a record one way answered within 2 s by one the
//     other way, both 92 to 404 bytes (a handshake message with any
//     plausible overhead, padding to a 256-byte bucket included), that
//     stands out: each of its two sizes new to its direction over the
//     rekey period before it, or its first record sent after 5 s with no
//     record of the band either way. A record of the size of one sent its
//     way within 2 s before it takes on that one's standing out: WireGuard
//     sends an initiation right after the packet that triggered it, and
//     padded to one bucket the two are one size. It shows the rhythm when
//     it stands out three times in a row, each 2 minutes to 3.5 minutes
//     after the one before; an exchange answered more than once within
//     2 s is one occurrence, standing out if any answer does. WireGuard
//     rekeys on the first packet past 2 minutes when it sends, past 165 s
//     when it only receives, so with a 25 s keepalive the gaps run from
//     120 s to about 190 s, and three rekeys can take up to 7 minutes of a
//     connection, up to about 10 minutes when batched (below).
//   - keepalive: an idle run, records of one size each sent after 5 s with
//     no record either way and not answered within 2 s, at one steady
//     interval (within 1 s): three of them once the connection has carried
//     an exchange of that band, five without. A record is judged once its
//     2 s have passed, on the connection's next packet, so a run shows on
//     the record after its third: three idle keepalives and one more.
//
// Only what stands out is chained, from the latest time it stood out, so a
// steady stream of records in the band (thinkpol's own 2 s path probes
// under 256-byte padding, a ping, an interactive or TURN stream), whatever
// its sizes and rate, and a request repeated at any interval shorter than
// 2 minutes never show the rhythm. Sizes must be new on their own, not
// only as a pair: random sizes at a few records a second make nearly every
// pair new, and pairs then chain by chance within 5 minutes. Measured: 6 minutes of
// random band sizes, from one exchange every 10 s to 50 a second, none
// flagged in 100 seeds at any rate. The price: a handshake pair hidden
// among identical records exchanged steadily (padded to one bucket, say)
// stands out only after 5 s quiet in the band, and is invisible while the
// tunnel carries such records. The keepalive signal has blind spots of its
// own: next to other steady traffic (those path probes, say) no record
// comes after 5 s of quiet, and when both peers send persistent
// keepalives in step each answers the other's within 2 s; in both, the
// rekey is the only signal. The "five without an exchange" rule almost
// never applies: TLS 1.3's NewSessionTicket and the first request usually
// make an exchange in the band.
//
// Records are kept by age, not count, so a burst of data around a rekey
// doesn't hide it, and stale exchanges are dropped at most once a rekey
// window, so a record's work is bounded by the band, not by the exchanges
// a connection carried. Records coalesced or split by the transport: a
// batching window leaves idle keepalives alone in their records, and a
// length written as a record of its own is a record like any other, so
// both still show. But WireGuard sends an initiation right after the
// packet that triggered it, so through a batching window the two share a
// record. Of batched rekeys only a keepalive-triggered one still shows:
// the record has one size each time, but the first handshake had no
// trigger, so the third of that size is the fourth handshake, up to about
// 10 minutes in. A batched rekey triggered by data, or sent while the
// tunnel is busy, leaves the pair's sizes changing or the band, and is missed
// whenever the tunnel is in use at the 2-minute mark (the idle keepalives,
// if any, still show). Measured false-positive risks on ordinary TLS,
// flagged by design: an identical request and response, both in the band,
// repeated at an interval of 2 to 3.5 minutes (HTTP/1.1 polling every 2
// minutes), and a server heartbeat, one unanswered record of one size at a
// steady idle interval (a server-sent events comment line). HTTP/2
// browsing with idle PINGs, a gRPC stream with keepalive PINGs (answered),
// a bulk download, HTTP/2 polling (its indexed request is below the band)
// and HTTP/1.1 polling every 30 s pass. Flow shape beyond that is not
// judged. A stream it can't frame from its first byte (not TLS, joined
// midstream, or with bytes it wasn't shown because a module before it
// dropped their packet) is never judged, and is tagged once,
// "wireguard-rhythm: stream not framed", so a pass for that reason shows
// in the verdict log.
//
// # Fully encrypted traffic, the prober and the server hello
//
// Three more of the M2 gate's checks judge what a disguised transport
// looks like: its first bytes, how its server answers strangers, and its
// server's hello. They tell a connection's client from its server by
// [Flow.Initiator]: for TCP the side that sent the SYN, for UDP the
// direction the censor saw first (the server's, for a flow already
// running when the censor started).
//
// fully-encrypted is the Great Firewall's passive detector (Wu et al.,
// USENIX Security 2023), on the first data a connection's client sends:
// over TCP the stream's first bytes as the server reads them (the first
// segment, with what an out-of-order segment joined to it), over UDP the
// first datagram, which Wu et al. didn't see judged and the lab judges
// anyway. It blocks (drop by default, pinned) unless an exemption applies:
// at most 3.4 or at least 4.6 set bits per byte (random bytes average 4);
// the first six bytes printable ASCII; more than half printable; a run of
// more than 20 printable; a TLS record header (handshake or application
// data) or an HTTP method. The server's direction and a connection joined
// midstream are not judged. The Great Firewall blocks only a fraction of
// such connections, to some address ranges; the lab blocks every one. A
// client that sends a first segment an exemption passes (six printable
// bytes, say) and the rest later passes too, as it does past the Great
// Firewall. With tagOnly it tags instead of blocking, for the prober.
//
// prober is the active prober: given a suspect TCP connection, it probes
// the connection's server, once per server address and port, from the
// router, and compares each answer with the reference's, the real site an
// entry would pretend to be (the camouflage target, a setting so the
// matrix can point it at any site). Suspects are what fully-encrypted
// tags and, with destinations set, every TCP connection to one once its
// client sent data; a UDP suspect is flagged Accept, "not probed". The
// probes: the suspect's first bytes replayed, random bytes of 3, 16, 49,
// 221 and 1000 bytes, and, when the suspect's ClientHello names the
// reference, a TLS handshake of the censor's own that reads the server
// hello's JA3S, JA4S, extensions in order and the negotiated ALPN (which
// TLS 1.3 sends encrypted, out of the ServerHello). A reaction is what
// came back (nothing, an echo, a TLS alert or handshake, an HTTP response,
// other bytes) and how the connection ended (closed, reset, or open at the
// timeout); a server whose reaction to any probe differs from the
// reference's, whose handshake differs, or that shows the upstream tell is
// flagged, its suspect connections blocked both ways and every later
// connection to or from it dropped, as the Great Firewall blocks a server
// its prober confirmed. A clean server is flagged Accept, the probes'
// results in the reason, so the verdict log says what was compared either
// way. Timing is reported (when each first answer came) and not judged:
// lab round trips are under a millisecond, too close for a relay's extra
// hop to stand out from noise.
//
// The upstream tell: an entry that relays what it doesn't recognize to the
// real site opens a connection of its own to the site for each probe.
// REALITY does so by design, on every connection, so the check may flag
// it: the matrix reports it as it is. The censor sees the entry's
// connection only from a vantage on the entry's uplink to the site. In
// the lab that is lab.Upstream, the camouflage target behind the router,
// where the entry's connection crosses the censor as a client's does; a
// real censor has it when the entry and the site are on different sides
// of it, never when both are beyond it. The tell is a connection from the
// probed address to a reference address starting during each probe, or
// within half a second after it, every probe of at least two; the servers
// of one address are probed one at a time so as not to blame one for
// another's connections, but a connection the entry's real clients cause
// during a probe still counts for it. An entry whose connection leaves
// from another address than the one probed (an IPv4 uplink for an IPv6
// probe) isn't matched.
//
// server-hello compares a real connection's server hello with the site's:
// on a TCP connection whose ClientHello names a listed site (the sites
// setting maps a name to the site's address, standing in for the DNS a
// real censor resolves it with), it reads the server's ServerHello, then
// sends the client's ClientHello, byte for byte, to the site and reads the
// site's: JA3S, JA4S, version, cipher, extensions in order and the ALPN
// the hello carries (TLS 1.2 and earlier). A difference flags the
// connection, both ways, and blocks the server, by address and port; a
// match is flagged Accept with both fingerprints. A server that relays a
// stranger's ClientHello to the site answers with the site's own hello and
// passes; this check is for the hello a server sends its own clients.
// What follows the ServerHello is not compared (TLS 1.3 encrypts it), nor
// is a server that answers with no ServerHello.
//
// # The verdict log
//
// One JSON [LogEntry] per line, buffered and flushed every 100 ms and when
// the censor stops, never synced: the first packet of a flow to get each
// verdict from each module, each tag and flag, the first packet of a flow
// whose payload was kept out for each reason, and, when the censor stops
// (or a flow starts over), one summary per flow with its packets by what
// the queue did with them and by why payload was kept out. A flow of a million packets is a handful of lines.
//
// # Whole datagrams
//
// The censor judges whole datagrams. Its nftables table references
// conntrack, which makes the kernel reassemble IP fragments, both
// families, before the forward hook, so a module sees a datagram the
// sender fragmented in one piece. A fragment that still reaches the censor
// escaped reassembly and is dropped, never passed unjudged: its later
// fragments carry no ports. The censor finds an IPv6 fragment header past
// any extension headers before it, AH included. Any other packet the censor can't parse (a
// malformed header) is accepted: no module can judge it, and the receiver
// discards it anyway.
//
// # The matrix
//
// lab's TestCensorMatrix scores every transport against every censor setup
// and regenerates lab/RESULTS.md. New transports join it by adding a probe:
// bring the transport up between device-a and server-1 through the router,
// and report whether data crossed over IPv4 and over IPv6. A cell passes
// only when both did and fails only when neither did: one family alone is
// partial, which no cell expects, so a blocking censor one family slips
// past is caught. A transport's cell without a censor runs first, and its
// censored cells are judged only once that one passed. Every cell is
// probed, and one whose censor can't be trusted (censord died, the kernel
// dropped queued packets ([QueueStats]), the verdict log lacks the probe's
// flows) is an error, which keeps lab/RESULTS.md from being written, and a
// blocked cell fails unless the verdict log blames the module its case
// names. Control rows check that plain TCP and HTTPS to an unlisted site on
// the underlay, what TLS-shaped transports ride, cross the censor and are
// seen by it; reference rows run real WireGuard (kernel) and OpenVPN (UDP
// and TCP), one tunnel per underlay family, on ports other than their
// defaults, their handshakes starting once the censor is up, so the
// fingerprint modules are judged on the real thing, on any port, and
// random-tcp, a naive echo server fed random bytes, is what a fully
// encrypted proxy looks like to fully-encrypted and the prober. A case
// with an active module probes twice and scores the second probe, once
// every flow of server-1 a passive module tagged has a flag: the prober
// judges a connection only after it crossed. Cases that compare with the
// camouflage site run in lab.Upstream, nginx serving it, and quote the
// module's verdict on the row's first connection in the cell.
//
// # Limits
//
// Verdicts are per direction, but for Throttle: a pinned Drop or Reset, or
// a flag, decides the flow it names, not its reverse. The flow table keeps
// every flow until the censor stops (a lab test's few thousand at most),
// and so does openvpn-fingerprint its state per connection (a few packet
// heads each), replaced only when the connection's addresses and ports
// carry a new one. A module learns of a flow's end only from the packets
// themselves (FIN, RST). A pinned Drop or Reset outlives the connection it
// blocked: a new SYN on the same addresses and ports is decided by it
// (dropped, or reset with an RST|ACK), so no SYN-ACK ever accepts the new
// connection and the flow never starts over; the ports stay blocked until
// the censor stops. That is deliberate (a fake SYN must not lift a pin),
// and it makes a pinned Drop or Reset residual censorship of its addresses
// and ports. Other verdicts end with their connection: a new connection on
// the same addresses and ports is judged anew, and a UDP flow silent for
// 120 s both ways is judged again from its next datagram.
//
// The stream reads a connection as a Linux receiver does for the cases
// above, not for every one. These still evade it, so a transport that
// passes by one of them proves nothing about a censor that reads them:
//
//   - a segment Linux discards that the censor reads: one whose ACK
//     acknowledges bytes never sent, or lies too far behind; one with a
//     stale timestamp (PAWS) or a bad TCP-MD5 or TCP-AO signature; data at
//     or past a FIN (this adds bytes, it hides none);
//   - a segment starting within 32 MiB of the next byte to read but past
//     the receiver's actual window: Linux discards it, the censor holds it
//     out of order, where it beats a later out-of-order copy of the same
//     bytes (never bytes that arrive in order);
//   - Linux merges out-of-order neighbours only while a buffer has
//     fragment slots and memory to spare; the censor always merges, which
//     changes which copy wins only for a copy starting at their joint;
//     which of two overlapping copies with different bytes Linux keeps
//     also depends on the shape of its out-of-order tree, which the
//     censor doesn't model;
//   - urgent data (URG) is read in the stream; a Linux receiver without
//     SO_OOBINLINE takes its last byte out of the stream;
//   - a receiver with TCP Fast Open on reads data on a SYN, which the
//     censor keeps out;
//   - past 16 KiB waiting out of order, the censor drops the farthest
//     bytes: if the gap before them fills and the sender never resends
//     them (the receiver kept them), the stream stops there.
//
// A TTL or hop limit that runs out past the censor can't happen in the
// lab: each server is the router's next hop.
package censor
