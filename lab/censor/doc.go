// Package censor is the lab's pluggable censor (PRD C4, TP-024;
// docs/design/lab.md "Censor lab"): a program in the lab router's container, censord, that
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
// module reading a server's hello finds the client's (JA3S, TP-026). A
// TCP flow carries a [Stream]: the sender's bytes in order, reassembled
// from segments that arrive out of order, overlap or repeat, with wrapping
// sequence numbers. The stream keeps its first 16 KiB as a prefix (a
// ClientHello split over two segments is one prefix once the second
// arrives) and, for each packet, the bytes it made readable in order
// ([Stream.Fresh]), past the prefix too, so a module can follow a whole
// stream over time (TLS record sizes, say) while the censor keeps only the
// prefix. Out-of-order bytes wait in at most 16 KiB; past that the stream
// breaks and delivers no more. A UDP flow keeps its first datagram
// instead. That retained payload ([Flow.Payload]) is what active modules
// get to replay. Flows also carry what a flow-level classifier times:
// when the flow started, its latest packet, its packet and byte counts.
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
//     once. It is TCP's only; on any other protocol the engine drops
//     instead. Throttle is a policer: a token bucket per flow at the
//     decision's rate (about 14 kbit/s unless the module says otherwise)
//     accepts or drops each packet with payload at once; nothing is held,
//     and a packet without payload always passes.
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
// Verdicts compose by one rule: only blocking verdicts (drop, reset,
// throttle) are terminal. The first passive module to block decides the
// packet; pinned, its verdict decides every later packet of the flow
// before any module looks. A pinned Accept is the module's alone: that
// module sees the flow no more, and the modules after it, and active
// modules' flags, may still block it. A flow's pinned verdict only ever
// gives way to a more severe one (drop and reset over throttle), so a flag
// never lifts a block and an Accept flag changes nothing.
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
// verdict from each module, each tag and flag, and, when the
// censor stops, one summary per flow with its packets by what the queue
// did with them. A flow of a million packets is a handful of lines.
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
// Verdicts are per direction: a pinned verdict or a flag decides the flow
// it names, not its reverse. The flow table keeps every flow until the
// censor stops (a lab test's few thousand at most). A module learns of a
// flow's end only from the packets themselves (FIN, RST).
package censor
