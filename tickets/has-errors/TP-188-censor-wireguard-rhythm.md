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
- [x] R1.1 (blocker): detection keys on exact WireGuard size arithmetic (a pair 56 bytes apart, one overhead both ways), so padding to 16 bytes or a per-direction overhead hides it while the 2-minute pairs and fixed-size idle records stay visible. Redesign around recurrence: (a) a rekey signal, a short two-record exchange in the handshake size band whose two sizes recur as the same pair 120–180 s later, at least twice; (b) a keepalive signal, records of one fixed size sent after the link was quiet, recurring at a steady interval. Flag on (a), or on (b) once a pair or a steady idle period is established. No dependence on the 56-byte difference or equal overhead. — Redesigned (modules_wgrhythm.go): rekey = an exchange of two band records (92–404 bytes, one each way within 2 s) whose sizes recur 3 times, each 120–180 s after an earlier one; keepalive = an idle run of one size (each after 5 s quiet, unanswered within 2 s, intervals within 1 s), 3 records beside an in-band exchange, 5 alone. No size arithmetic, no equal overhead; flagged with padding to 16 and 256, and 19/40 overhead per direction.
- [x] R1.2 (blocker): the 32-record cap evicts the initiation on a busy tunnel; keep candidate handshake records by age (the pair window), not count. Test: the timeline with a high-rate burst around each rekey is still flagged. — Band records kept per size by age (wgPairWindow), out-of-band records not kept at all; "busy around each rekey" (1200-byte records every 250 µs, ±100 ms around each initiation) is flagged at the third rekey.
- [x] R1.3 (should-fix): a bad-checksum decoy marks the direction unframed for good; return Accept early on p.BadChecksum. Test with one badsum segment after the TLS handshake. — Inspect returns Accept on p.BadChecksum before touching state; TestWGRhythmBadChecksum (one 100-byte badsum segment after the TLS handshake, then the rhythm: flagged at 85 s).
- [x] R1.4 (should-fix): false positives on ordinary TLS (any 3 same-size small records plus one coincidental pair). Count keepalive-sized records only after a quiet period and as a steady recurrence. Negative tests: HTTP/2 with idle PINGs, a gRPC keepalive stream, a bulk download, a client polling every ~2 minutes; what still flags goes into lab/censor/doc.go as a named false-positive risk. — Idle records count only after 5 s quiet, unanswered, at a steady interval. TestWGRhythmOrdinaryTLS: HTTP/2 browsing with idle PINGs, a gRPC stream with keepalive PINGs, a bulk download and HTTP/2 polling pass; HTTP/1.1 polling (every 2 min and every 30 s, request and response in band) and a server-sent events heartbeat are flagged, pinned in the test and named in lab/censor/doc.go as measured false-positive risks.
- [x] R1.5 (should-fix): the "rhythm removed" control keeps a fixed record every 25 s while idle. Make the control remove the rhythm (jittered timing and sizes), and add "sizes hidden, rhythm kept", which must be flagged. — The control is jittered (each record padded by a random 0–255 bytes, each idle keepalive moved up to ±10 s; 20 seeds) and passes; "sizes hidden, keepalives kept" and "sizes hidden, rekey kept" (padded to 256) are flagged.
- [x] R1.6 (should-fix): coalescing and splitting: test a timeline through a batching window (idle keepalives and idle handshakes still flagged), say in lab/censor/doc.go what a coalesced handshake under load does; also a length prefix written as its own record. — Through a 20 ms batching window idle keepalives and idle handshakes are flagged; a length written as its own record is flagged both ways; a handshake batched with data under load is missed, pinned by TestWGRhythmCoalescedHandshakeUnderLoad and stated in lab/censor/doc.go.
- [x] R1.7 (nits): notTLS → unframed with a comment; a Tag once when a stream becomes unframed ("wireguard-rhythm: stream not framed"); doc wording ("at least `keepalives` (3) of them", "a test shortens it"); drop the unused wgRun.t; dropNth.Name() returns "drop-nth". — notTLS → unframed with a comment; Inspect returns the Tag "wireguard-rhythm: stream not framed" once, on the transition (TestWGRhythmNeedsTLS checks one tag on the unframed flow, none on a framed one); doc wording fixed; wgRun.t dropped; dropNth.Name() is "drop-nth".

- [ ] R2.1 (blocker): an occurrence chains to any earlier occurrence at least `rekey` old without checking the pair stayed away in between, so a steady two-way stream of in-band records (2 s path probes under 256-byte padding, a ping probe, TURN-over-TLS) is flagged after ~240 s. Count an occurrence as a rekey candidate only if its pair was not seen during the previous rekey period, or it starts after a quiet period in the band; chain only from the latest previous candidate, with a gap in the rekey window; say in doc.go a pair hidden among identical steady records is invisible. Negative tests: steady in-band two-way streams (equal and random in-band sizes) for 6 minutes at 1, 10 and 50 records/s; path-probe-like 2 s request/reply under 256-byte padding; HTTP/1.1 polling every 30 s must pass. Pin whatever still flags at low rates and name it in doc.go.
- [ ] R2.2 (should-fix): past 1024 exchange keys every exchange() call walks the whole map inside censord's serial packet path. Prune at most once per keep interval (any 'seen' map too). A benchmark or a test bounding the work per record.
- [ ] R2.3 (should-fix): WireGuard rekeys on the first packet after the deadline, so gaps of 165–190 s occur and keep = rekey*3/2 drops anything over 180 s. Widen the window (+30 s slack); timelines whose rekey is triggered by a keepalive or a data packet sent 0–1 ms before the initiation, gaps 125 s and 190 s, must be flagged; 'three pairs 240 s apart' still passes.
- [ ] R2.4 (should-fix, pin + doc): crossed keepalives (both peers at k·25 s, 20 ms apart) count as answered and the keepalive signal never fires. Add TestWGRhythmCrossedKeepalives pinning the result; doc.go: the rekey signal is then the only one, and next to other steady traffic (2 s path probes) the 5 s idle condition never holds.
- [ ] R2.5 (should-fix, doc): a batched initiation shares a record with the packet that triggered it, so batching hides the rekey whenever the tunnel is in use at the 2-minute mark; make the 'batched, rekey' test realistic (a keepalive or data message just before each initiation) and state the result in doc.go.
- [ ] R2.6 (should-fix, doc): 'about 4 minutes' is optimistic; say 'up to 7 minutes, or three idle keepalives' in lab/README.md, doc.go and the results_test.go row comment.
- [ ] R2.7 (nits): doc.go: the 'five without an exchange' rule almost never applies (TLS 1.3 NewSessionTicket plus the first request form an in-band exchange); the record completing an idle run flags before its 2 s answer window has passed: judge the run when the window closes, or document it.
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
- 2026-11-07 round 1 fixes: lab/censor/modules_wgrhythm.go reads recurrence (the rekey exchange recurring 3 times a rekey period apart; a steady run of unanswered idle records), keeps band records by age, ignores bad-checksum packets, tags an unframed stream once; docs: lab/censor/doc.go (signals, coalescing, measured false-positive risks), lab/README.md, the matrix row's comment in lab/results_test.go
- 2026-11-07 round 1 tests: TestWGRhythmFlagsTheRhythm (plain, padded to 16 and 256, overhead per direction, busy around each rekey, batched, length prefixed; whole records and 3-byte segments), TestWGRhythmCoalescedHandshakeUnderLoad, TestWGRhythmRemovedPasses (jittered control, 20 seeds; partial rhythms), TestWGRhythmSteadyIdlePeriodAlone, TestWGRhythmOrdinaryTLS, TestWGRhythmBadChecksum; TestWGRhythmNeedsTLS checks the unframed tag
- 2026-11-07 round 1 mutations, each failed a test: band records cleared by any out-of-band record (a count cap of one); bad-checksum guard dropped; rekey occurrences 3→2; rekey lower bound dropped; rekey upper bound 1.5×→3×; pair window 2 s→5 s; handshake band dropped; answered idle records counted; quiet period dropped; steady-interval check dropped; alone-threshold +2 dropped; exchanged never set; unframed tag dropped; idle run of any size; band record not kept; flag only one direction; midstream guard dropped; delivered-bytes guard dropped; TLS header check dropped; app-data filter dropped; pending idle record never confirmed; new-connection lookup and stale-state delete dropped; record header split mishandled; record body split mishandled
- 2026-11-07 round 1 verification: `make lint` and `make test` green; merged origin/rewrite twice; full `make lab-test` green on 74ecbf1 (LAB_P=4, lab 568 s, node 37 packages); lab/RESULTS.md unchanged (no matrix change). A first lab run on 5da4eb0 was stopped by me before results to land a doc-comment fix; its containers removed with `make lab-down`
- 2026-11-07 not verified: real WireGuard-in-TLS traffic through censord (no such transport yet). Out of scope (orchestrator: TP-029/TP-087): the matrix probe must run two rekey periods (about 4 minutes) for this row to mean anything
- 2026-11-07 has-errors → review
- 2026-11-07 review → has-errors (round 2 findings R2.x)
