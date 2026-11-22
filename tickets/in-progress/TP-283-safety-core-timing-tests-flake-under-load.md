---
id: TP-283
title: "The safety core's timing tests flake under load"
milestone: M2
area: tooling
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-082]
refs: []
needs_human: decision
owner: agent-tp-283
branch: tp-283-safety-timing-tests
---

## Goal
The device-test safety core's timing tests and the self-test's 10 s bound pass on a loaded lab runner, so a `make lab-test` failure there means a broken core, not a busy machine.

## Scope
- `lab/devicetest/safety/deadman_test.go` (~:108-117), "a fresh heartbeat holds it until the limit": a 100 ms deadline held by a 30 ms heartbeat. It failed once on a shared runner at a load average of about 29 on 6 cores (a targeted COUNT=3 re-run passed). Since TP-082 it runs uncached on the host in every `make lab-test` (the Makefile's labpkgs phase runs `go test -tags lab -count=1` over `./lab/...`), as well as in a node.
- The self-test's deaf case (a capture that sees nothing) needs about 9.1 s of its 10 s bound when tcpdump is slow to start: the capture start waits up to 5 s for tcpdump's header (`safety/capture.go` ~:92, `waitHeader`), then two `capture_seen` waits of 2 s each (`selftest.go` ~:143). `TestABrokenCaptureStopsTheRunWithin10s` bounds the whole run by the test's own clock, so a slow start under load can fail it.
- The core is frozen (`FROZEN`, `TestTheSafetyCoreIsFrozen`): any change to it, its tests included, needs the owner's approval. That approval is the decision this ticket needs.
- Ideas: widen the core's test deadlines (e.g. a 500 ms deadline, 100 ms heartbeat); or run the core's timing tests only in the node phase or the long stream, not in the host labpkgs phase; for the self-test, a shorter header wait or a bound the deaf case keeps with margin.

## Out of scope
- The core's behaviour on a device: only its tests' timing.

## Acceptance
- [x] The owner's decision recorded in Notes.
- [ ] No failure of the core's timing tests or `TestABrokenCaptureStopsTheRunWithin10s` in N loaded runs (N in the decision, e.g. 20 under `make lab-test` load), the runs and their load in the Log.
- [ ] Every new or changed test mutation-checked, mutations in the Log.

## Notes
- Found in TP-082's last round (2026-11-22).
- Decision (owner, 2026-11-22): widen the core's timing test deadlines only; the core's own code (its non-test files) doesn't change. The self-test's 10 s bound (TP-082's acceptance) stays and is only measured under load. N = 20 loaded runs.

## Log
- 2026-11-22 created in backlog (from TP-082's last round)
- 2026-11-22 backlog → in-progress, owner: agent-tp-283
- 2026-11-22 deadman_test.go: "a fresh heartbeat holds it until the limit" now deadline 500 ms, stale 1 s, limit 3 s, heartbeat every 100 ms for 8 s (was 100 ms / 300 ms / 1.2 s / 30 ms for 5 s); "a heartbeat that goes stale" now deadline 500 ms, stale 1 s, heartbeat every 100 ms for 2 s, fire no earlier than 2 s (was 100 ms / 300 ms / 30 ms for 600 ms). A beat may now be late by 900 ms (was 270 ms) before the heartbeat counts as stale. No other test in the core has a bound that load can break: the rest are lower bounds, negative waits or eventually-waits of 5 s or more. The core's non-test files are unchanged. FROZEN: only deadman_test.go's line, f5aa6284…e2d799 → 2235a76a…270db0.
- 2026-11-22 mutations (in deadman.go, never committed): the heartbeat ignored (fires at the deadline) → "a fresh heartbeat holds it" fails (fired at 500 ms, "deadline"); the limit case removed → it fails ("deadline" at 9 s, not "limit"); a stale heartbeat still holding (stale check removed) → "a heartbeat that goes stale" fails (still watching after 10 s).
