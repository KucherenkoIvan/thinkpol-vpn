---
id: TP-263
title: "Slow node-phase packages: packettest, routetable, path"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: agent-tp-263
branch: tp-263-slow-node-packages
---

## Goal
Cold, internal/dataplane/packettest took 8m31s, internal/dataplane/routetable 7m49s and internal/dataplane/path 7m33s in the node phase; a node cache miss on any of them takes half the budget. The owner wants a full lab to take at most 15 minutes on the remote runner. Measured 2026-11-19 on rewrite cb0348d6 with every lab-speed ticket merged: 23m12s cold and 23m8s with the node phase fully cached; all tests passed; the lab/ package alone took ~22 minutes; lab slot waits median 60–73 s, max 9–11 min; `docker compose up` per lab median 46–78 s; 57–111 lab starts per run.

## Scope
- Find where each package spends its time: fixed sleeps, real timers that could be sped up or injected, serial subtests that could be parallel, per-test setup.
- Cut it without weakening what the tests prove (TP-241's rules: watch state, speed up clocks).

## Acceptance
- [x] Per-package time before and after (cold) in Notes. (Notes, "Before and after".)
- [x] Each of the three under 3 minutes cold, or the reason it can't be. (Without the wait for a lab slot all three take under 2 minutes. With it: packettest 88 s and routetable 161 s after, but path 222 s, 126 s of which was waiting for a slot that other runs' labs held. The minutes in the full lab are that same wait, which the packages can't change: Notes, "Where the time goes".)
- [x] No test weakened: mutations named for any changed oracle. (No oracle changed: the diff only adds `t.Parallel()` to 11 routetable tests, no assertion, bound or wait touched, so no mutation applies. 5× in the lab under load, and 5× with `-race` on the host.)

## Notes

### Where the time goes
A package's time in the node phase (`GoTestResult.Elapsed`, lab/gotest.go `inLab`) counts from the start of its lab to its teardown. That covers the wait for a lab slot (the host-wide cap, shared with the `lab/` phase's tests), `docker compose up`, the tests and `down`. The tests themselves are a small part of it:

| package | tests in the node (before) | what slows them |
|---|---|---|
| packettest | 0.00 s (2 pure tests) | nothing: building and parsing packets |
| path | ~4 s serial, 12.7 s package wall on a loaded host | nothing above 1.8 s; liveness on 150 ms real-time windows (`fastOptions`), already parallel per semantics |
| routetable | 79 s of tests, ~68 s wall; 41.9 s on the host (without the 5 lab tests) | 14 tests that wait on `RetryAfter` (5 s) or the kernel ran one after another |

The 8m31s / 7m49s / 7m33s from the full lab are mostly slot waits (that run's slot waits reached 9–11 min). The node phase isn't on the full lab's critical path either: 23m12s cold vs 23m8s fully cached.

### Change
routetable: `t.Parallel()` on 8 fake-driven tests that wait for `RetryAfter` or the watcher (guard_test.go, routetable_test.go) and on 3 of the 5 lab tests (routetable_linux_test.go). Three tests stay serial, so they have the CPU to themselves (review R1.2): TestEnforcerAppliesChangesAndReappliesOnEvents counts the Applies of a burst against a 200 ms debounce window, and TestTheGuardComesBackOnItsOwn (3 s bounds) and TestCountrySizedTable (20 s bounds, ~23k prefixes) time themselves. The lab tests can run in parallel: each builds its own pair of namespaces with random names (`newDevice`), and netcfg's owner lock is per namespace (keyed by the nsfs inode), as is the nft guard. Package wall on the host: 41.9 s → 12.2 s. The new floor is TestTheGuardIsPutBackWhileTheRoutesFail (10.4 s: two real `RetryAfter` retries). Injecting `RetryAfter` would take that to ~1 s, but it's a product timer in root code for ~10 s, so it isn't done. path and packettest are unchanged: path's serial tests add up to ~4 s, and making its real-time liveness tests share CPU with more peers risks flakes for no real gain.

### Before and after
Lab runs, `make lab-gotest PKG=… COUNT=1`, each package alone, cold, on a runner other sessions kept loaded (slot wait and `up` from `THINKPOL_LAB_TIMELINE`; tests+down is from the end of `up` to the end of the run):

| package | before (ea0cfa48) | after (9037fb1c) |
|---|---|---|
| packettest | 232 s: slot 155 s, up 35 s, tests+down 9 s | 88 s: slot 42 s, up 10 s, tests+down 22 s |
| path | 148 s: slot 82 s, up 33 s, tests+down 24 s | 222 s: slot 126 s, up 34 s, tests+down 43 s |
| routetable | 162 s: slot 42 s, up 34 s, tests+down 77 s | 161 s: slot 75 s, up 10 s, tests+down 40 s |

Wall without the slot wait: before 77 / 66 / 120 s, after 46 / 96 / 86 s. packettest and path didn't change: their differences are load. All three in one lab-gotest (packages in parallel): 279 s before, 263 s on d66ffbcc.

### Out of scope (findings)
- The node phase's per-package time includes the slot wait, so a package looks slow when it only queued. Reporting the wait apart from the run would point lab-speed work at the right place.
- packettest and path never need root or a namespace (no test reads `THINKPOL_LAB`). Each still costs a container start and a slot for 0–13 s of tests. Running such packages without a node, or several in one node, would save container starts on every cold run. That's a lab design change and would need a ticket.
- In two runs, 25–26 s passed between a lab getting its slot and asking for the subnet lock (timeline: routetable after, packettest before). Not investigated.

## Review findings
Round 1 (2026-11-19): merge, no shared state found.
- [x] R1.1 The 5 lab tests are the first in internal/dataplane to run real Enforcers (netcfg, the nft guard, netlink) at once in one process, and neither the host `-race` run (they skip there) nor lab-gotest (no `-race`) covered that. Run them once with `-race` in a lab node. — The lab builds node test binaries without cgo, and `-race` needs cgo, so lab-gotest can't. Done by hand: the package's tests built with `-race` (cgo, linked static) into the checkout's ignored lab/.run/, a lab started with `make lab-up`, the binary run in device-a as lab-gotest runs it (root, THINKPOL_LAB=1, the package directory), then `make lab-down`. On 59a15fa4: 53 top-level tests passed, none skipped, no data race reported.
- [x] R1.2 TestEnforcerAppliesChangesAndReappliesOnEvents expects exactly 3 Applies within a 200 ms debounce window from a burst of 5 events, and the 3 s bounds of TestTheGuardComesBackOnItsOwn now share the CPU with TestCountrySizedTable: keep those three serial. — `t.Parallel()` removed from the three, with a comment on each saying why; the other 11 stay parallel (Notes, "Change").

## Log
- 2026-11-19 created in backlog (full-lab measurement on rewrite cb0348d6)
- 2026-11-19 backlog → in-progress, owner: agent-tp-263
- 2026-11-19 measured the three packages alone, cold: their tests take 0 s (packettest), ~4 s (path) and ~68 s (routetable); the rest is the lab's slot wait, compose up and teardown (Notes)
- 2026-11-19 routetable: t.Parallel on 14 tests that wait on RetryAfter or the kernel; host package wall 41.9 s → 12.2 s, tests+down in a node 77 s → 40 s. No oracle changed, so no mutation applies; path and packettest unchanged (reasons in Notes)
- 2026-11-19 runs on 9037fb1c: the three packages 5× in the lab under load (`make lab-gotest … COUNT=5`): 495 passed, 0 failed; routetable 5× with -race on the host: ok
- 2026-11-19 on d66ffbcc (rewrite merged in): `make lint` ok, `make test` ok, `make lab-gotest` of the three packages COUNT=1: ok, 99 passed, 263 s. No full lab: brief's lab rule (2026-11-18), targeted runs only; a mutation run wasn't possible on the Mac (heavy work there is paused) and isn't needed with no oracle changed
- 2026-11-19 in-progress → review
- 2026-11-19 review round 1: R1.1–R1.2, merge
- 2026-11-19 R1.2: the three time-bounded routetable tests serial again (59a15fa4). R1.1: the package's tests with `-race` in a lab node (by hand, the lab builds without cgo): 53 passed, no race. On 59a15fa4: `make lint` ok, `make test` ok, `make lab-gotest PKG=./internal/dataplane/routetable COUNT=5` under load: 345 passed, 0 failed
