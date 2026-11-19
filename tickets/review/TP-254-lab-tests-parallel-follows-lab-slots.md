---
id: TP-254
title: "Lab tests run as many at once as the machine's lab slots allow"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-254"
branch: "tp-254-lab-parallel-follows-slots"
---

## Goal
A full `make lab-test` runs as many labs at once as the machine's lab-slot cap allows, so the default stream gets closer to the owner's 15-minute target (2026-11-16). TP-247 found (2026-11-19) that the `lab/` test binary runs with Go's default `-test.parallel` (GOMAXPROCS), below the 12-lab slot cap, so the matrix's row labs and the other parallel lab tests queue behind each other. The node phase runs `labctl gotest -p $(LAB_P)`, and the machine's CPU-slot wrapper sets `LAB_P` to the job's CPU weight (3 for a full lab), so at most 3 node packages run at once although each mostly waits on containers. The owner's rule (2026-11-16): weights are machine-agnostic, and how much work runs at a time is decided by the machine's configuration; for labs, the lab-slot cap is that configuration. The full lab's default stream took 34m12s, with lab starts waiting up to ~3 min for a slot.

## Scope
- The lab streams' test binaries (`lab/` and the other `./lab/...` packages, both streams, the harness phase) run with `-test.parallel` equal to the machine's lab-slot cap: the same `THINKPOL_LAB_MAX_LABS` the slots read (default 12), through one Make variable, so a machine sets it in its environment.
- The node phase's `labctl gotest` runs as many packages at once as that cap; `LAB_P` keeps bounding only the CPU-bound part, the package test builds.
- lab/README.md says how concurrency is set.

## Out of scope
- The slot cap itself (`THINKPOL_LAB_MAX_LABS`, its default).
- `make lab-gotest`'s concurrency.

## Acceptance
- [x] lab/ and node-phase concurrency follow the lab-slot cap (Makefile, README).
- [x] Full-lab default stream before and after, in Notes (budget report: wall, slot waits, slowest tests).
- [x] No new failures from the higher concurrency (full lab green, or failures shown unrelated by targeted re-runs).

## Notes
- Makefile: `LAB_SLOTS = $(or $(THINKPOL_LAB_MAX_LABS),12)`, the cap the slots read (`TestMakefileConcurrencyFollowsLabSlots` checks its default against `defaultMaxLabs` in lab/hostlock.go). Every lab test run in a stream or the harness phase gets it: `-test.parallel=$(LAB_SLOTS)` on both streams' `lab.test`, `-parallel $(LAB_SLOTS)` on both streams' `go test` of the other `./lab/...` packages and on `LAB_HARNESS_GOTEST`. The node phase runs `labctl gotest -p $(LAB_SLOTS) -build-p $(LAB_P)`. Set in the environment or on the command line, `THINKPOL_LAB_MAX_LABS` reaches both the variable and the recipes' environment (checked with GNU make: unset 12, environment 7, command line 5).
- lab/gotest.go: `GoTestEach` takes `builds` beside `parallel`. A package compiles its tests and checks the cache under the build gate (`LAB_P`), then lets go of it and waits for the lab gate (`LAB_SLOTS`). Builds run ahead of the labs, and a cached package never takes a lab gate. `labctl gotest -build-p` (default 4, like `-p`).
- To measure slot waits, each lab start now writes a `slot-wait <duration> <project>` line to `THINKPOL_LAB_TIMELINE` (lab/timeline.go, lab/lab.go).
- Before: TP-247's full lab on 27ba73b3 (its own branch, with the matrix rows split into 15 labs; not this branch's code): 2053 s wall, default stream 34m12s, long 4m6s, node phase uncached (40 packages ran). Its lab starts took 16 s to 2m53s each, slot wait included. Slowest: TestCensorMatrix/https_(control) 14m28s, wireguard_(reference) 12m6s, TestKillSwitchUnderSystemd/down 7m30s, lab/censor 7m0s.
- After, run 1 (05fbcee9, node phase uncached: 40 packages, 0 cached; the harness phase ran because the harness hash changed; another full lab and a matrix run were on the machine at the start): 1729 s wall, default stream 28m49s, long 11m58s. All tests passed and RESULTS.md was assembled. Slot waits over this run's 101 labs: median 147 s, mean 272 s, max 18m49s, 74 over a minute. Slowest tests (their times include slot waits): TestHarnessCommandStartsSealed 18m10s, TestHarnessLabsBelongToTheirCheckout 18m5s, TestHealthWithAnExitThatNeverHandshakes 18m0s, TestDisconnectLeavesNothingBehind 17m25s, internal/agent/supervisor 17m24s. Lowest available memory 4386 MB, from a 10 s sample.
- After, run 2 (05fbcee9, node phase warm: 40 of 40 cached; harness stamped, not run; this run's labs held all 12 slots at its peak): 923 s wall, default stream 15m24s (24 s over the 15m budget), long 2m53s. All tests passed and RESULTS.md was assembled. Slot waits over 51 labs: median 4 s, mean 24 s, max 140 s, 9 over a minute. Slowest tests: TestCensorMatrix/openvpn-tcp_(reference) 7m22s, reality 7m4s, openvpn-udp_(reference) 6m42s, TestEgressThroughAnExit 6m2s, https_(control) 5m43s. Lowest available memory 2785 MB.
- The queue moved from Go's `-parallel` to the slots. With the node phase uncached, the default stream fell from 34m12s to 28m49s, but slot waits make up much of every slow test's time. Run 1 also shared its slots with other runs, so it does not isolate this change from the load. With a warm node cache, the default stream is 15m24s, and the remaining time is the matrix rows (5–7 min each, all started at once). No lab ran this branch's code at the old concurrency, so before and after compare different matrix layouts (TP-247's split rows vs rewrite's one lab per row).

## Log
- 2026-11-19 created in backlog (lab-speed follow-ups)
- 2026-11-19 backlog → in-progress, owner: agent-tp-254
- 2026-11-19 Makefile LAB_SLOTS from THINKPOL_LAB_MAX_LABS: -parallel on the streams' and harness phase's lab test runs, node phase -p LAB_SLOTS -build-p LAB_P; GoTestEach build and lab gates; slot waits in the lab timeline; lab/README.md "Tests under load", Environment.
- 2026-11-19 tests: TestMakefileConcurrencyFollowsLabSlots (mutations: LAB_SLOTS default 11; the long stream's lab.test without -test.parallel; LAB_HARNESS_GOTEST without -parallel; node phase -p $(LAB_P): each fails it), TestTimelineNotesSlotWait (mutations: the line written to another file; the wait's sign reversed: each fails it). The gates in GoTestEach have no unit test (they need Docker); the full labs ran the node phase through them (40 packages uncached in run 1).
- 2026-11-19 make lint, make test green on 05fbcee9; full make lab-test twice on 05fbcee9: 1729 s (default 28m49s, node uncached) and 923 s (default 15m24s, node cached), both all tests passed, over budget only (Notes).
- 2026-11-19 out of scope: the slot cap is shared by every run on the machine and slots are taken by polling, not in order, so a run with many waiting labs takes most free slots; under the budget report, slow tests' times are mostly slot waits when runs overlap.
- 2026-11-19 in-progress → review
