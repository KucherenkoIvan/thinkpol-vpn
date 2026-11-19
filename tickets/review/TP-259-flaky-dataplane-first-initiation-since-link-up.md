---
id: TP-259
title: "Flaky internal/dataplane TestTheFirstInitiationSinceLinkUpIsFromTheNeighborsUpSince under load"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-259"
branch: "tp-259-first-initiation-flake"
---

## Goal
internal/dataplane's TestTheFirstInitiationSinceLinkUpIsFromTheNeighborsUpSince failed once in `make test` and once in a targeted run of 20 under load (TP-252's runs, 2026-11-19); a second `make test` passed. Find the timing assumption it makes and fix it: watch state, don't lengthen a sleep.

## Scope
- Reproduce under load, name the timing assumption, fix the test (or the code, if the code is wrong).

## Out of scope

## Acceptance
- [x] The root cause named in Notes, with evidence.
- [x] A fix.
- [x] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [x] No retries and no longer timeouts without a cause.

## Notes
- Root cause: the test fixture's `node.start` listened before it applied the section. `memory.Listen` snapshots the inbound table then, empty, and a running listener picks up the applied table later on its own goroutine (`watchPeers`). When device-a dialed before that goroutine ran, the dial got a camouflaged link: its packets go nowhere and nothing answers. A dialer leaves such a link only when DeadAfter passes on its path clock without a proof, and this test holds device-a's path clock still. So device-a probed once at link creation, never again, never closed the link, and the test waited out its 10 s with the neighbor down. Evidence, from 8 parallel copies × 25 runs beside a CPU hog: 6 of 200 and 2 of 200 failed, every failure at the deadline with device-a's one link never proven (PacketsIn 0, PacketsOut 3: one probe and two initiations) and, in a diagnostic run, server-1 with no neighbor at all: it never accepted the link. Production is unaffected: a real clock moves, so DeadAfter closes the unanswered link and the dialer redials.
- Fix: `node.start` applies the section before it listens, so the listener's first snapshot admits the section's inbound links. A later table change still reaches a running listener through `watchPeers`, as before.
- Seen in TP-252's runs: once in `make test` under heavy load, once in a targeted `-count 20`. The package doesn't import lab/censor.

## Log
- 2026-11-19 created in backlog (TP-252 review)
- 2026-11-19 backlog → in-progress, owner: agent-tp-259
- 2026-11-19 reproduced on rewrite 85a286ae: 8 parallel copies × 25 runs of the test binary beside a CPU hog failed 6/200 and 2/200, all at the 10 s deadline with device-a's link unproven; a diagnostic run showed server-1 with no neighbor (Notes).
- 2026-11-19 cb0708c5: internal/dataplane/engine_test.go node.start applies the section before it listens. No sleep, retry or timeout changed. Under the same load: 600/600 pass (three batches of 8 × 25).
- 2026-11-19 mutations: M1 (start listens before it applies again, the cause back) fails 3/200 under the same load; M2 (memory watchPeers sleeps 50 ms per table change, a slow goroutine on demand) with the fix passes 20/20, M1+M2 fails 5/5 at the deadline. Both restored.
- 2026-11-19 cb0708c5: internal/dataplane -count=3 ok; make lab-gotest PKG=./internal/dataplane/ ok (43 pass, 0 fail, ~68 s). Merged origin/rewrite (8f2cc15f, lab/ and tickets only): make lint, make test green. No full lab-test: the change is one test helper in a package lab-gotest covered; the brief asks for none.
- 2026-11-19 in-progress → review
