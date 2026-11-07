---
id: TP-195
title: "Health grades an exit by its WireGuard handshake"
milestone: M2
area: agent
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

## Log
- 2026-11-07 created in backlog
- 2026-11-07 backlog → in-progress, owner: agent-tp-195
- 2026-11-07 unit tests: TestExitsUnansweredPastTheDeadline, TestAnExitThatNeverHandshakesIsExitNoHandshake, TestHealth (two exit cases), wg TestAnUnansweredHandshakeStaysPendingUntilOneCompletes; mutations, each caught: pending reset on every initiation, a response not clearing pending, `>=` deadline → `>`, the Exit check dropped, all-exits-down graded degraded, the engine's Exit flag always false
- 2026-11-07 `make lint`, `make test` green on 746b0c8; lab TestHealthWithAnExitThatNeverHandshakes passes (device-a → server-1 → server-2, server-2's handshake initiations dropped: `health: down: exit_no_handshake`, then ok once they pass); mutation, caught: the engine's Exit flag always false (no exit_no_handshake within 90 s)
- 2026-11-07 full `make lab-test` green on 8a657d2 (GOFLAGS=-p=2, LAB_P=1, under the CPU lock); not verified: a real device (macOS/Android) showing exit_no_handshake in the tray
- 2026-11-07 in-progress → review
