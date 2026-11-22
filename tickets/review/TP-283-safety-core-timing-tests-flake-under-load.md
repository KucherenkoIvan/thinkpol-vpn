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
- [x] No failure of the core's timing tests or `TestABrokenCaptureStopsTheRunWithin10s` in N loaded runs (N in the decision, e.g. 20 under `make lab-test` load), the runs and their load in the Log.
- [x] Every new or changed test mutation-checked, mutations in the Log.

## Notes
- Found in TP-082's last round (2026-11-22).
- Decision (owner, 2026-11-22): widen the core's timing test deadlines only; the core's own code (its non-test files) doesn't change. The self-test's 10 s bound (TP-082's acceptance) stays and is only measured under load. N = 20 loaded runs.
- Decision (owner, 2026-11-22): merge without a device self-test run; the change touches only `deadman_test.go` and its `FROZEN` line, none of the core's code.
- Decision (owner, 2026-11-22): the self-test's 10 s bound and its margin under heavy load (worst 9.824 s at a load of ~30) are accepted as they are, to be watched.

## Log
- 2026-11-22 created in backlog (from TP-082's last round)
- 2026-11-22 backlog → in-progress, owner: agent-tp-283
- 2026-11-22 deadman_test.go: "a fresh heartbeat holds it until the limit" now deadline 500 ms, stale 1 s, limit 3 s, heartbeat every 100 ms for 8 s (was 100 ms / 300 ms / 1.2 s / 30 ms for 5 s); "a heartbeat that goes stale" now deadline 500 ms, stale 1 s, heartbeat every 100 ms for 2 s, fire no earlier than 2 s (was 100 ms / 300 ms / 30 ms for 600 ms). A beat may now be late by 900 ms (was 270 ms) before the heartbeat counts as stale. No other test in the core has a bound that load can break: the rest are lower bounds, negative waits or eventually-waits of 5 s or more. The core's non-test files are unchanged. FROZEN: only deadman_test.go's line, f5aa6284…e2d799 → 2235a76a…270db0.
- 2026-11-22 mutations (in deadman.go, never committed): the heartbeat ignored (fires at the deadline) → "a fresh heartbeat holds it" fails (fired at 500 ms, "deadline"); the limit case removed → it fails ("deadline" at 9 s, not "limit"); a stale heartbeat still holding (stale check removed) → "a heartbeat that goes stale" fails (still watching after 10 s).
- 2026-11-22 loaded runs, all on 32c0e1fd, each beside a full `make lab-test` of rewrite e4cc326d (both passed, default stream 14m38s and 14m28s): `make lab-gotest PKG=./lab/devicetest/... COUNT=20 LAB_NOCACHE=1` passed (1053 s): TestTheDeadmanFiresWhenItMustAndOnlyThen 20/20 and TestABrokenCaptureStopsTheRunWithin10s 20/20 (both subtests), 1-min load average 9-31 on 6 cores while lab/devicetest ran. A second round, `PKG=./lab/devicetest/safety/... COUNT=20 LAB_NOCACHE=1`, passed (1044 s): the dead-man test 20/20, at a 1-min load of 10-38 for its first ~12 minutes, then falling to 2 as the full lab ended. Host labpkgs path, `go test -tags lab -count=20 ./lab/devicetest/safety/` under umask 022: 20/20 passed (209 s, 1-min load 11-30). The first host round is void: it ran plain `go test` without the umask 022 the Makefile's test recipes set, so every test's temp dir was refused as group-writable, before any timing was involved. Failures: none.
- 2026-11-22 the self-test's 10 s bound, measured and unchanged (capture.go, selftest.go, run_linux_test.go untouched): the deaf case ("it sees nothing") took 5.6-9.8 s across the 20 loaded runs, max 9.824 s at a load of ~30, a 176 ms margin; "no such interface" took 1.3-4.5 s. It held in all 20, but the margin under heavy load is thin; whether to act on it is a new owner decision.
- 2026-11-22 `make lint` and `make test` green on 32c0e1fd; `go test ./lab/devicetest/...` on a Mac passes (TestTheSafetyCoreIsFrozen included). No full `make lab-test` on the branch: the only change is the core's dead-man test, run 40 times in a node and 20 on the host above. Not verified: the device self-test run doc.go ("Frozen") asks for before a change to the core merges; that is the owner's to run.
- 2026-11-22 in-progress → review
- 2026-11-22 owner decisions recorded in Notes: merge without a device self-test run; the 10 s bound's margin under load accepted, to be watched.
