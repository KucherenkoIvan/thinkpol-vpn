---
id: TP-195
title: "Health grades an exit by its WireGuard handshake"
milestone: M2
area: agent
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-140]
refs: []
owner: "agent-tp-195"
branch: "tp-195-exit-handshake-health"
---

## Goal
Health is not "ok" while a peer the device routes through (an exit, directly or behind a relay) has never completed a WireGuard handshake or has gone silent past a deadline.

## Scope
Today health counts only neighbours (the first hop). Device → entry → exit with the entry up and the exit never answering reads ok, and so does a direct exit whose link is proven but whose handshake never completes. TP-140 recorded this in RESIDUAL-RISKS.md and its Notes.

## Out of scope
None named.

## Acceptance
- [x] a unit test: an exit peer with no handshake past the deadline raises a problem (snake_case code); one that handshakes clears it
- [x] lab: device → relay → exit with the exit's WireGuard blocked shows the problem in `thinkpol status`
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- From TP-140's round-1 reviews, 2026-11-07. On the MVP path (orchestrator's call): the tray and daily use read health.
- Proposed follow-up (round-1 review, not built): replace the log parsing with a conn.Bind wrapper around the path.Bind that watches outbound WireGuard messages by type: a type-1 (initiation) sent to a peer's endpoint sets its pending time, a type-2 (response) received from or sent to it clears it. That drops the dependence on wireguard-go's log wording and works with the verbose log off.
- Grading: a chain has one exit (netmap.Chain.Exit), so R1.1's "none of the default chain's exits is live while one is unanswered" is that exit unanswered; "live" isn't computed. If chains get several exits, exitHandshakes needs it.

## Review findings
- [ ] R1.1 grading: an exit is unanswered (pending past the deadline), live (a handshake within RejectAfterTime) or neither, computed in one function called from statusWith; down when the default route goes through a chain and none of that chain's exits is live while one is unanswered, any other unanswered exit degraded; table tests; ProblemExitNoHandshake comment and both api-overview files say exactly this
- [ ] R1.2 docs say a flag stays until a later handshake completes, even if the device goes idle (wg/doc.go, HandshakePendingSince comment, api-overview-reference.md, api-overview.md, RR48)
- [ ] R1.3 a real-wireguard-go test of the responder-side clear (Sending handshake response)
- [ ] R1.4 the deadline constant in internal/dataplane, no wg import in agent; test-knob plumbing simplified where natural
- [ ] R1.5 wg/doc.go names the three wireguard-go log strings this depends on and the test guarding them
- [ ] R1.6 a peer removed, or re-added with another Node, forgets its pending time; tested
- [ ] R1.7 no exit_no_handshake while the exit's first hop is down; the deadline restarts when the link returns; tested
- [ ] R1.8 nits: handshakeLog → handshakes with a constructor; comment wording (deadline ~30 s to notice a dead session, RR48, api-overview.md:200, dataPlaneProblems); a steady-traffic test over several deadlines stays ok

## Log
- 2026-11-07 created in backlog
- 2026-11-07 backlog → in-progress, owner: agent-tp-195
- 2026-11-07 unit tests: TestExitsUnansweredPastTheDeadline, TestAnExitThatNeverHandshakesIsExitNoHandshake, TestHealth (two exit cases), wg TestAnUnansweredHandshakeStaysPendingUntilOneCompletes; mutations, each caught: pending reset on every initiation, a response not clearing pending, `>=` deadline → `>`, the Exit check dropped, all-exits-down graded degraded, the engine's Exit flag always false
- 2026-11-07 `make lint`, `make test` green on 746b0c8; lab TestHealthWithAnExitThatNeverHandshakes passes (device-a → server-1 → server-2, server-2's handshake initiations dropped: `health: down: exit_no_handshake`, then ok once they pass); mutation, caught: the engine's Exit flag always false (no exit_no_handshake within 90 s)
- 2026-11-07 full `make lab-test` green on 8a657d2 (GOFLAGS=-p=2, LAB_P=1, under the CPU lock); not verified: a real device (macOS/Android) showing exit_no_handshake in the tray
- 2026-11-07 in-progress → review
- 2026-11-07 review → has-errors (round 1 findings R1.x)
