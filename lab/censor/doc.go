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
// advertises. The queue hands packets over with full checksums (without
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
// retired modules, tags), when its addresses and ports carry a new
// connection, so a new connection is read and judged from its own first
// byte: TCP once a SYN with a new sequence number is accepted by the
// SYN-ACK acknowledging it, both directions at once (a SYN alone restarts
// nothing, since a receiver with the connection open ignores it, so it
// can't shake off a pinned verdict); UDP after 120 s without a packet,
// Linux conntrack's timeout for a UDP flow with replies. The old flow's
// summary is logged then.
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
// framework, and are not censors of their own: block-ip decides packets
// by destination (optionally only those with payload, so a handshake
// completes first), and replay, passive and active at once, tags a TCP
// flow to its destinations once its stream holds a whole TLS record and
// replays the retained bytes to the flow's destination from the router.
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
// lab's TestCensorMatrix scores every transport against every censor
// setup and regenerates lab/RESULTS.md. New transports join it by adding a
// probe: bring the transport up between device-a and server-1 through the
// router, and report whether data crossed over IPv4 and over IPv6. A cell
// passes only when both did and fails only when neither did: one family
// alone is partial, which no cell expects, so a blocking censor one
// family slips past is caught. A transport's cell without a censor runs
// first, and its censored cells are judged only once that one passed.
// Every cell is probed, and one whose censor can't be trusted (censord
// died, the kernel dropped queued packets ([QueueStats]), the verdict log
// lacks the probe's flows) is an error, which keeps lab/RESULTS.md from
// being written. A plain-tcp (control) row checks that plain TCP on the
// underlay, what TLS-shaped transports ride, crosses the censor and is
// seen by it.
//
// # Limits
//
// Verdicts are per direction, but for Throttle: a pinned Drop or Reset, or
// a flag, decides the flow it names, not its reverse. The flow table keeps
// every flow until the censor stops (a lab test's few thousand at most). A
// module learns of a flow's end only from the packets themselves (FIN,
// RST). A blocked connection's verdict ends with it: a new connection on
// its addresses and ports is judged anew, and a UDP flow silent for 120 s
// is judged again from its next datagram; blocking an address and port
// for a while after (residual censorship) is a module's own business.
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
//   - a receiver with TCP Fast Open on reads data on a SYN, which the
//     censor keeps out;
//   - past 16 KiB waiting out of order, the censor drops the farthest
//     bytes: if the gap before them fills and the sender never resends
//     them (the receiver kept them), the stream stops there.
//
// A TTL or hop limit that runs out past the censor can't happen in the
// lab: each server is the router's next hop.
package censor
