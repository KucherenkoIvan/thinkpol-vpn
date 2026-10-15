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
- What TP-024 round 2 delivers: RST toward the client, active-module channels, matrix TCP probe, fragment policy at the queue.

## Acceptance
- [ ] a two-segment TLS ClientHello is visible to passive modules as one prefix on the flow
- [ ] reverse flows link for JA3S computation
- [ ] throttling uses mark/tc or a policer, not NFQUEUE hold
- [ ] verdict log is bounded per flow for long runs

## Log
- 2026-10-15 created in backlog (split from TP-024 review)
