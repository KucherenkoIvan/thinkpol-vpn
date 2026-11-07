---
id: TP-188
title: "Censor module: WireGuard rhythm inside TLS"
milestone: M2
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-089]
refs: [C1, C4, C6, docs/design/milestones.md#milestones, docs/design/lab.md#censor-lab]
owner: "agent-tp-188"
branch: "tp-188-censor-wireguard-rhythm"
---

## Goal
The lab catches a TLS flow that carries WireGuard with its rhythm showing: the 2-minute rekey pair and the fixed-size keepalive records. It is one of the checks `reality` must pass at the M2 gate (docs/design/milestones.md).

## Scope
- A censor-lab module that reads a flow's record sizes and timing and flags the WireGuard rhythm: a handshake-sized pair of records every 2 minutes, and fixed-size keepalive records.
- Test traffic: `udp`-in-TLS-like flows with the rhythm, and the same traffic with the rhythm removed.
- A row for the module in the M2 acceptance matrix (TP-029).

## Out of scope
- Flow shape beyond the rhythm (packet-size distributions, burst patterns): not tested at M2 (owner, 2026-11-07).
- Shaping in any transport: C6, `reality` in TP-087.

## Acceptance
- [x] `udp`-in-TLS-like test traffic with the rhythm is flagged
- [x] the same traffic with the rhythm removed passes
- [x] the module runs in the M2 acceptance matrix
- [x] `make lint`, `make test` and the censor lab tests pass

## Notes
- If `reality` fails it with default settings, the fix is a minimal padding/batching default in the transport, not a full shaping module (owner, 2026-11-07).

## Review findings
- [ ] R1.1 (blocker): detection keys on exact WireGuard size arithmetic (a pair 56 bytes apart, one overhead both ways), so padding to 16 bytes or a per-direction overhead hides it while the 2-minute pairs and fixed-size idle records stay visible. Redesign around recurrence: (a) a rekey signal, a short two-record exchange in the handshake size band whose two sizes recur as the same pair 120–180 s later, at least twice; (b) a keepalive signal, records of one fixed size sent after the link was quiet, recurring at a steady interval. Flag on (a), or on (b) once a pair or a steady idle period is established. No dependence on the 56-byte difference or equal overhead.
- [ ] R1.2 (blocker): the 32-record cap evicts the initiation on a busy tunnel; keep candidate handshake records by age (the pair window), not count. Test: the timeline with a high-rate burst around each rekey is still flagged.
- [ ] R1.3 (should-fix): a bad-checksum decoy marks the direction unframed for good; return Accept early on p.BadChecksum. Test with one badsum segment after the TLS handshake.
- [ ] R1.4 (should-fix): false positives on ordinary TLS (any 3 same-size small records plus one coincidental pair). Count keepalive-sized records only after a quiet period and as a steady recurrence. Negative tests: HTTP/2 with idle PINGs, a gRPC keepalive stream, a bulk download, a client polling every ~2 minutes; what still flags goes into lab/censor/doc.go as a named false-positive risk.
- [ ] R1.5 (should-fix): the "rhythm removed" control keeps a fixed record every 25 s while idle. Make the control remove the rhythm (jittered timing and sizes), and add "sizes hidden, rhythm kept", which must be flagged.
- [ ] R1.6 (should-fix): coalescing and splitting: test a timeline through a batching window (idle keepalives and idle handshakes still flagged), say in lab/censor/doc.go what a coalesced handshake under load does; also a length prefix written as its own record.
- [ ] R1.7 (nits): notTLS → unframed with a comment; a Tag once when a stream becomes unframed ("wireguard-rhythm: stream not framed"); doc wording ("at least `keepalives` (3) of them", "a test shortens it"); drop the unused wgRun.t; dropNth.Name() returns "drop-nth".

## Log
- 2026-11-07 created in backlog
- 2026-11-07 backlog → in-progress, owner: agent-tp-188
- 2026-11-07 done: lab/censor/modules_wgrhythm.go, the `wireguard-rhythm` module: frames each TCP stream's TLS records; a handshake pair is an app-data record and one 56 bytes shorter the other way within 2 s (initiation 148, response 92, plus the transport's overhead); the rhythm is two pairs of one overhead a rekey period apart (120 s to 180 s) or a pair plus 3 keepalive-sized records (32 + overhead); blocks both ways. Docs: lab/censor/doc.go, docs/design/lab.md, lab/README.md
- 2026-11-07 evidence: TestWGRhythmFlagsTheRhythm (a 260 s udp-in-TLS-like timeline, whole records and 3-byte segments: flagged at the 3rd keepalive, or without keepalives at the 2nd rekey pair; nothing passes after, either way); TestWGRhythmRemovedPasses (the same timeline padded to 256-byte multiples passes; so do partial rhythms); TestWGRhythmNeedsTLS, TestWGRhythmNewConnection, TestWGRhythmFramesOnlyWhatItSaw, TestWGRhythmSettings
- 2026-11-07 mutations, each failed a test: pair window dropped; rekey lower bound dropped; rekey upper bound dropped; keepalive count 3→2; keepalives of a neighbouring overhead counted; pair looked up in its own direction; TLS header check dropped (and its type and version halves alone); app-data filter dropped; header split across segments mishandled; flag only one direction; reset verdict built as drop; midstream guard dropped; delivered-bytes guard dropped; new-connection lookup and stale-state delete dropped together (each alone survives: the other covers it, since the engine shows the SYN-ACK first)
- 2026-11-07 matrix: a `wireguard-rhythm` row in TestCensorMatrix (lab/results_test.go); plain-tcp and udp pass it (neither is TLS). Full `make lab-test` green on bda28c2 (lab 488 s, node 36 packages); lab/RESULTS.md regenerated by that run
- 2026-11-07 not verified: real WireGuard-in-TLS traffic through censord (no such transport yet; the flagged path is covered through the engine with synthetic traffic). Out of scope, for TP-087/TP-029: matrix probes last ~30 s, so a `reality` cell against this row means something only when its probe runs for minutes (past a rekey or 3 idle keepalives)
- 2026-11-07 in-progress → review
- 2026-11-07 review → has-errors (round 1 findings R1.x)
