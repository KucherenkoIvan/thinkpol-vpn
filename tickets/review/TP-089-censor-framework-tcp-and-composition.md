---
id: TP-089
title: "Censor framework: TCP reassembly and composition"
milestone: M2
area: lab/censor
repo: thinkpol-vpn
size: M
depends_on: [TP-024]
split_from: TP-024
refs: [C4, docs/design/lab.md#censor-lab]
owner: agent-tp-089-fix1
branch: tp-089-censor-framework-tcp-and-composition
---

## Goal
The censor framework can inspect multi-segment TCP handshakes, link reverse flows for server-side fingerprints, and compose module verdicts without the round-2 scope of TP-024.

## Scope
- Per-flow TCP stream reassembly: a reassembled prefix on `Flow` (a uTLS ClientHello with X25519MLKEM768 is about 1.8 KB over two segments, SNI often in the second).
- Reverse-flow linking (for JA3S in TP-026).
- Payload retention for prober replay.
- A module that is both passive and active, or passive tagging of suspected flows for an active module.
- Mark- or policer-based throttling (`SetVerdictWithMark` plus nft/tc, or a token bucket), not held packets (review S3).
- Verdict-log volume: once per flow plus a summary, buffered (review S8).
- Pinned-Accept composition: per-module, or only blocking verdicts are terminal (review S9).
- RSTs to both ends of a TCP connection.
- Topology for TP-026's upstream tell: the entry→target connection does not cross the router today.

## Out of scope
- What TP-024 delivers (through its round 3): RSTs toward the client only; a per-module channel of new flows that never blocks the queue; IP fragments reassembled before the queue for both families, with any fragment that escapes reassembly dropped; the matrix's `plain-tcp (control)` row and both-family probes; a verdict log without fsync.

## Acceptance
- [x] a two-segment TLS ClientHello is visible to passive modules as one prefix on the flow
- [x] reverse flows link for JA3S computation
- [x] a flow's payload is retained (bounded) for an active module to replay, and a lab test replays a captured ClientHello from it
- [x] one module can be passive and active at once, or a passive module tags a suspect flow that an active module then receives
- [x] composition: a module's pinned Accept no longer stops a later module (or a flagging active module) from blocking the flow, with a unit test of the chosen rule (review S9)
- [x] a Reset verdict sends RSTs to both ends, and a lab test sees one at device-a and one at server-1
- [x] the topology for TP-026's upstream tell is decided and built: the entry → camouflage-target connection crosses a censor point, and a lab test sees it there
- [x] throttling uses mark/tc or a policer, not NFQUEUE hold
- [x] verdict log is bounded per flow for long runs
- [x] the matrix scorer fails a blocking cell where only one family was blocked (`lab/results_test.go` `score`/`blockedBy`: today "only IPv4" or "only IPv6" scores `fail`, which a blocking cell expects, so a one-family leak stays green)
- [x] userspace `isFragment` walks past AH (and any IPv6 extension header) to a fragment header (`lab/censor/packet.go:173-178`); nft `exthdr` already drops these before the queue

## Notes
- TP-024 round-3 merge check (Grok): the two acceptance items above are leftovers from TP-024 review, not gaps in TP-024's delivered scope.

## Review findings
- [x] R1.1 (blocker) Throttle ends the module walk; a later Drop/Reset must still win, pinned or not
- [x] R1.2 insertion: bad-checksum, no-ACK and SYN-data segments enter the stream though the receiver discards them
- [x] R1.3 far-future segments break the stream; ignore beyond a receive-window bound, log them
- [x] R1.4 same-offset out-of-order overlap keeps the newest copy; Linux keeps the first
- [x] R1.5 a reused 4-tuple inherits the old flow (stream, retired modules, pinned Accept)
- [x] R1.6 IPv6 later fragment: the walk parses fragment data as headers
- [x] R1.7 lab RST test checks the RST arrived, not that the connection was torn down
- [x] R1.8 throttle polices one direction only; police both or document

## Log
- 2026-10-15 created in backlog (split from TP-024 review)
- 2026-10-15 docs (TP-024 round 3): acceptance for payload retention, passive-plus-active modules, composition, RSTs to both ends and the upstream-tell topology; out of scope corrected to what TP-024 delivers
- 2026-10-16 docs(board): two acceptance items from TP-024 round-3 merge check (matrix one-family leak scoring; userspace IPv6 ext-header walk)
- 2026-10-31 backlog → in-progress, owner: agent-tp-089
- 2026-10-31 isFragment now reads lab/ip.Decode's new Fragment flag; Decode walks AH (4-byte units) and every RFC 6564 extension header (mutation: AH case renamed away, TestDecodeIPv6FragmentBehindAH and TestIsFragment's AH cases fail)
- 2026-10-31 design choices not settled by the docs (options; the smallest that keeps later modules possible was picked): (1) streams: per-direction `Flow.Stream` with a 16 KiB prefix plus `Fresh()`, the in-order bytes each packet made readable past the prefix too, so a later flow-level classifier can follow a whole stream over time (alternatives: prefix only, which hides everything past 16 KiB; keeping whole streams, unbounded). UDP keeps its first datagram. Out-of-order bytes are capped at 16 KiB, then the stream is `Broken()`. (2) passive→active: both. `Decision.Tag` publishes a snapshot with the retained payload to active modules (so TP-026's FET heuristic can feed its prober), and a `RegisterPassive` module that also implements `Active` runs as both. (3) composition: only blocking verdicts are terminal. A pinned Accept retires only its module, and a flow's verdict only gives way to a more severe one (Drop/Reset > Throttle > Accept), so flags never lift a block (alternative: per-module verdicts with a vote, which no module needs yet). (4) throttle: a userspace token bucket per flow (`Decision.Rate`/`Burst`, default 1750 B/s, about 14 kbit/s), packets without payload pass, nothing held (alternatives: mark + nft limit or tc, which need per-flow kernel state and a second chain). (5) verdict log: one decision entry per (verdict, module) a flow gets, tag/flag entries, one summary per flow at shutdown, bufio flushed every 100 ms. (6) upstream tell: `lab.Upstream()` puts a `camouflage` node on its own `world` network behind the router (alternative: a second censor point, which needs a second censord). (7) matrix: a one-family result scores `partial`, which no cell expects. Verdicts stay per direction (doc.go Limits)
- 2026-10-31 two proof modules, not censors of their own: block-ip gains `data` (decide only packets with payload) and `rate`/`burst` (replacing `hold`/`held`); `replay` (passive+active) tags a TCP flow once its stream holds a whole TLS record and replays the retained bytes from the router. RSTs: `rstToReceiver` (seq = the dropped packet's, only when it carries ACK) is sent next to `rstToSender`
- 2026-10-31 tests: stream_test.go (in order, out of order, repeats/overlap, wrap, midstream, bounds), compose_test.go (two-segment Go ClientHello of 1503 B with SNI past byte 100, in and out of order; reverse links; composition; severity; flag merge; tag once; replay as one passive+active value; log bounded incl. alternation), engine_test.go policer with an injected clock, TestRSTToReceiver, TestBlockIPDataOnly, TestQueuePipeline/polices (in-node NFQUEUE), lab: TestTCPResetReachesBothEnds, TestCensorReplaysClientHello, TestCensorSeesUpstream, TestScore
- 2026-10-31 mutations, each seen failing then restored: no out-of-order buffer (StreamOutOfOrder, StreamRepeats, StreamWraps, StreamBounds, TwoSegmentClientHello); no reverse link (LinksReverseFlows); pinned Accept terminal (CompositionAcceptIsNotTerminal, Severity); pin always replaces (Severity); flag always replaces (FlagsMergeBySeverity); tag every time (TagReachesActive); no dual Build (ReplayIsPassiveAndActive); replay before the record is whole (ReplayIsPassiveAndActive); log every packet, and log on every change instead of once per verdict and module (LogBoundedPerFlow; the latter 1001 lines); policer always passes (ThrottlePolices, PinnedThrottle, and in the lab TestQueuePipeline/polices: 40 of 40 crossed); receiver RST at seq+len (RSTToReceiver); block-ip data ignored (DataOnly); score one family as fail (TestScore). Lab, one run with three mutations at once (GOFLAGS -run on the three tests): no receiver RST → TestTCPResetReachesBothEnds fails at server-1; replay ignores tags → TestCensorReplaysClientHello gets the ClientHello once; server-1 joined to `world` → TestCensorSeesUpstream: the censor didn't see the connection
- 2026-10-31 docs: lab/censor/doc.go rewritten for streams, tags, composition, policer, RSTs, log, limits; docs/design/lab.md gains the composition rule, RSTs to both ends, the policer, `lab.Upstream` and `partial`; lab/README.md names `lab.Upstream()`
- 2026-10-31 not verified: the replay lab test splits the ClientHello itself (100 bytes, a pause, the rest) because the image's openssl (bookworm, 3.0) sends a one-segment ClientHello; the bytes are a real Go ClientHello with X25519MLKEM768, which is 1503 B and would span two segments anyway. TCP Fast Open data on a SYN is handled in Stream but not exercised in the lab
- 2026-10-31 make lint and make test green; full make lab-test green on 53d0f5a (rewrite merged in at a0ab02c; LAB_P=1 beside other runs): lab/ ok, 36 packages in nodes ok
- 2026-10-31 out of scope, for the orchestrator: the RESULTS.md header the matrix writes still says "fail when it didn't"; `partial` never reaches a written file (a partial cell fails the run), so the header was left as generated
- 2026-10-31 in-progress → review
- 2026-10-31 review → has-errors (round 1: 1 blocker, 7 should-fix)
- 2026-10-31 has-errors → in-progress, owner: agent-tp-089-fix1
- 2026-10-31 R1.1: only Drop and Reset end the module walk; a Throttle, pinned or not, is the floor and a later module's Drop/Reset wins; a module that pins any verdict retires from the flow. Test TestEngineCompositionThrottleIsNotTerminal (both orders, pinned and not). Mutations: unpinned Throttle ends the walk (fails 3 cases), pinned Throttle decides before the walk (fails 4)
- 2026-10-31 R1.8: police both directions (small): the first Throttle applied to a flow pins the same throttle on its reverse, now or when the reverse first shows up, each direction with its own bucket; the bucket keeps the first throttle's rate (documented). Test TestEngineThrottlePolicesBothDirections. Mutations: no pin on an existing reverse, no pin on a reverse created later (each fails one case)
- 2026-10-31 R1.2: decodePacket verifies TCP/UDP checksums (Packet.BadChecksum; IPv4 UDP 0 = none, IPv6 UDP 0 = bad); the stream keeps out bad-checksum payload, data without ACK, data on an RST, and SYN data (Linux without TFO; lab servers don't enable it). Content modules are told to read the stream, not Packet.Payload. Checksum offload: without NFQA_CFG_F_GSO the kernel completes checksums before copying to the queue; the lab's stream tests (replay, matrix) pass with the check on, which they couldn't if packets arrived with partial checksums. Tests TestDecodePacketChecksum, TestStreamKeepsOutWhatReceiverDiscards, TestEngineIgnoresWhatReceiverDiscards. Mutations: checksum never bad; SYN data read; no-ACK data read; RST data read; observe reads bad checksums; ignore logged every time (each fails its test)
- 2026-10-31 R1.3: segments starting 32 MiB or more past the next in-order byte are ignored (bound: several times the 6 MiB max of Linux's default tcp_rmem; the lab kernel's actual tcp_rmem not checked); a full out-of-order buffer now drops its farthest bytes instead of breaking the stream (in-window far junk could break it too, so the bound alone wasn't enough); every kept-out reason, eviction included, logs once per flow (EventIgnore) and the summary counts them (LogEntry.Ignored). Tests TestStreamFarSegments, TestStreamBounds (rewritten). Mutations: no window bound; break instead of evict; a broken stream reads nothing more (old behaviour: fails Bounds and FarSegments). Not done: tracking each receiver's advertised window (window field + wscale) would close the gap between the real window and 32 MiB; documented in Limits
- 2026-10-31 R1.4: out-of-order holding follows tcp_data_queue_ofo: a copy whose bytes all wait already is dropped (first copy wins at one offset), a same-start longer copy replaces, a copy starting at a neighbour's end merges into it, later copies covered whole are dropped. Bigger than "keep the first": without the merge, a longer copy at the joint of two adjacent segments would win where Linux keeps the merged bytes. Not modelled: Linux stops merging when an skb runs out of fragment slots or memory (Limits). Test TestStreamOverlapKeepsLinuxBytes. Mutations: same-offset drop removed; merge removed (each fails it); dropping later covered copies is byte-equivalent on delivery (by reading, not run), so no test can tell it apart
- 2026-10-31 R1.5: a TCP flow starts over (both directions, old summaries logged, new-flow snapshot published) when a SYN with a new ISN is accepted by a SYN-ACK acknowledging it; deviation from the DECIDED line: a SYN alone restarts nothing, since restarting on it would let a client shake off a pinned Drop with a fake SYN the server ignores. A SYN after FIN/RST or after idle is covered by "new ISN". UDP starts over after 120 s without a good-checksum datagram (conntrack's UDP stream timeout); a bad-checksum datagram keeps nothing alive. Test TestEngineNewConnectionStartsOver. Mutations: no restart at the SYN-ACK; restart on a bare SYN; restart on a bad-checksum SYN-ACK; no UDP idle restart; bad checksum refreshes Last (each fails it)
- 2026-10-31 R1.6: ip.Decode stops the IPv6 header walk at a later fragment. Test TestDecodeIPv6LaterFragmentDataIsNotHeaders. Mutation: no break (Decode fails, ok=false)
- 2026-10-31 R1.7: TestTCPResetReachesBothEnds also checks server-1 has no established connection on the port after the RST, and that neither end sends another packet on the connection after its RST. Lab mutations, one run each with -run on that test: receiver RST at seq+1 → server-1 sends a challenge ACK (0x10) and device-a answers it with RST, both reported; receiver RST at seq+2^30 → server-1 keeps the connection established. Unmodified, the test passes
- 2026-10-31 nits: RST|ACK acknowledging the SYN toward a reset SYN-ACK's receiver (TestRSTToReceiver; mutation: plain RST, fails); a rejected flag no longer marks the log and the dead f.last store is gone (not observable, no test); RESULTS.md header says what partial means; doc.go no longer cites TP-024. Not done (not in touched lines, or not trivial): replay's full-size record check, a name registered as both passive and active, O(n^2) out-of-order inserts, a pinned Reset answering an endpoint's RST
- 2026-10-31 docs: lab/censor/doc.go (streams, discards, out-of-order rules, flows starting over, composition, connection policer, verdict log, Limits listing what still evades the stream: ACK of unsent data, PAWS, TCP-MD5/AO, FIN-slot data, junk between the real window and 32 MiB, merge limits, TFO receivers, out-of-order eviction stalls, residual blocking left to modules); censor.go Decision/Passive/Throttle; docs/design/lab.md censor paragraph; lab/README.md points at the Limits
- 2026-10-31 origin/rewrite merged twice (b4d3fb9, 4f61321), nothing in lab/censor. make lint and make test green on 4f61321; full make lab-test green on 4f61321 (LAB_P=4, no other lab running): lab/ ok, 36 packages in nodes ok; RESULTS.md regenerated by that run, header only
- 2026-10-31 out of scope, for the orchestrator: per-receiver window tracking (above); a QUIC/UDP module will want its own notion of a session beyond the 120 s idle rule
- 2026-10-31 in-progress → review
