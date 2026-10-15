---
id: TP-089
title: "Censor framework: TCP reassembly and composition"
milestone: M2
area: lab/censor
repo: thinkpol-vpn
size: M
depends_on: [TP-024]
split_from: TP-024
refs: [C4, DESIGN#censor-lab]
owner: ""
branch: ""
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
- [ ] a two-segment TLS ClientHello is visible to passive modules as one prefix on the flow
- [ ] reverse flows link for JA3S computation
- [ ] a flow's payload is retained (bounded) for an active module to replay, and a lab test replays a captured ClientHello from it
- [ ] one module can be passive and active at once, or a passive module tags a suspect flow that an active module then receives
- [ ] composition: a module's pinned Accept no longer stops a later module (or a flagging active module) from blocking the flow, with a unit test of the chosen rule (review S9)
- [ ] a Reset verdict sends RSTs to both ends, and a lab test sees one at device-a and one at server-1
- [ ] the topology for TP-026's upstream tell is decided and built: the entry → camouflage-target connection crosses a censor point, and a lab test sees it there
- [ ] throttling uses mark/tc or a policer, not NFQUEUE hold
- [ ] verdict log is bounded per flow for long runs
- [ ] the matrix scorer fails a blocking cell where only one family was blocked (`lab/results_test.go` `score`/`blockedBy`: today "only IPv4" or "only IPv6" scores `fail`, which a blocking cell expects, so a one-family leak stays green)
- [ ] userspace `isFragment` walks past AH (and any IPv6 extension header) to a fragment header (`lab/censor/packet.go:173-178`); nft `exthdr` already drops these before the queue

## Notes
- TP-024 round-3 merge check (Grok): the two acceptance items above are leftovers from TP-024 review, not gaps in TP-024's delivered scope.

## Log
- 2026-10-15 created in backlog (split from TP-024 review)
- 2026-10-15 docs (TP-024 round 3): acceptance for payload retention, passive-plus-active modules, composition, RSTs to both ends and the upstream-tell topology; out of scope corrected to what TP-024 delivers
- 2026-10-16 docs(board): two acceptance items from TP-024 round-3 merge check (matrix one-family leak scoring; userspace IPv6 ext-header walk)
