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
// silently censor less). The engine tracks per-flow state ([Flow]: counts,
// and a verdict pinned to the flow) and writes every decision, with its
// module and reason, to a verdict log, one JSON [LogEntry] per line, that
// the tests read.
//
// # Modules
//
// Modules register from init ([RegisterPassive], [RegisterActive]), like
// cmd/thinkpol's commands, and are either:
//
//   - [Passive]: shown every packet until one of them decides, and
//     returning a [Decision]: accept, drop, reset or throttle. Reset is an
//     RST the censor sends itself toward the packet's sender, with a
//     sequence number that sender believes, and the packet is dropped; it
//     is TCP's only, and on any other protocol the engine drops instead.
//     Throttle today holds the packet for a while (500 ms unless the module
//     says otherwise) and then accepts or drops it; TP-089 replaces the
//     hold with marks or a policer. A module may pin its verdict to the
//     flow, and later packets of the flow are decided the same way without
//     the modules seeing them again.
//   - [Active]: acting on their own (the prober, TP-026). They are fed each
//     new flow the censor sees, may probe and flag flows ([FlagFunc]), and
//     give no per-packet verdict of their own; a flagged flow's verdict is
//     applied like a passive module's pinned one. Feeding them never makes
//     the queue wait: a new flow an active module has no room for is
//     counted ([Engine.Unnoticed]) and skipped.
//
// New modules join by registering themselves. block-ip decides packets by
// destination: it is what proves the framework end to end.
//
// # Whole datagrams
//
// The censor judges whole datagrams. Its nftables table references
// conntrack, which makes the kernel reassemble IP fragments, both
// families, before the forward hook, so a module sees a datagram the
// sender fragmented in one piece. A fragment that still reaches the censor
// escaped reassembly and is dropped, never passed unjudged: its later
// fragments carry no ports. Any other packet the censor can't parse (a
// malformed header) is accepted: no module can judge it, and the receiver
// discards it anyway.
//
// # The matrix
//
// lab's TestCensorMatrix scores every transport against every censor
// setup and regenerates lab/RESULTS.md. New transports join it by adding a
// probe: bring the transport up between device-a and server-1 through the
// router, and report whether data crossed over IPv4 and over IPv6. A cell
// passes only when both did. A transport's cell without a censor runs
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
// The framework judges packets, not streams: it doesn't reassemble TCP,
// so a module sees a handshake split across segments only in pieces; a
// [FlowKey] is one direction, so nothing links a flow to its replies; no
// payload is kept past the packet; a module is passive or active, never
// both; and verdicts don't compose: the first passive module that decides
// wins. Modules that need any of these (stream fingerprints, the prober's
// follow-ups) wait for them (TP-089).
package censor
