---
id: TP-287
title: "The default stream takes free lab slots first"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-287"
branch: "tp-287-default-stream-slots-first"
---

## Goal
A full `make lab-test` stays within the default stream's 15-minute budget while long-stream lab tests run beside it. Lab slots go first come, first served across runs (TP-260's ticket queue in the lock directory, lab/hostlock.go), so a long-stream lab that queued earlier takes a freed slot ahead of a default-stream lab that waits, and the default stream, the one under the budget, loses minutes. Measured on tp-080-path-liveness (2026-11-23, which adds long-stream lab tests holding up to 7 labs for minutes): with the long stream capped at 3 parallel tests (`LAB_LONG_PARALLEL ?= 3`) the default stream took 15m24s (24 s over, exit 3), the long stream 13m55s, total 15m24s; at cap 2, default 15m10s and total 21m44s. The censor matrix waits up to ~3 min at the start for a free slot. rewrite alone runs the default stream in ~12m26s. Every lab test already knows its stream: `THINKPOL_LAB_STREAM` is `default` or `long` under `make lab-test` (lab/README.md, "Streams"). Give the default stream first pick of a freed slot.

## Scope
- A freed slot goes to the oldest waiter of the default stream when one is waiting, else to the oldest waiter of any kind; a waiter outside a stream counts as default.
- A waiter's class comes from `THINKPOL_LAB_STREAM` and is recorded in its queue entry, so other runs' waiters see it.
- Order within a class stays first come, first served across runs.
- A dead waiter still leaves the queue without blocking anyone or leaking a slot: TP-260's guarantees keep holding.
- lab/README.md and lab/hostlock.go's docs say how slots are handed out.

## Out of scope
- The slot cap (`THINKPOL_LAB_MAX_LABS`), `LAB_LONG_PARALLEL`, test bodies.

## Acceptance
- [x] (a) A long-stream waiter that queued earlier does not take a freed slot while a default-stream waiter waits. Test with concurrent waiters; mutation: plain FIFO → the test fails.
- [x] (b) Within one class, arrival order holds, and a long-stream waiter still gets a slot when no default waiter is left (test).
- [x] (c) A dead waiter of either class leaks no slot and blocks no one (the existing tests still pass, extended to both classes).
- [x] (d) Measured: one full `make lab-test` of tp-080-path-liveness with this branch merged in: its default, long and total times, its exit, and the censor matrix's first slot wait, against the 3-parallel run above.
- [x] (e) Measured: one full `make lab-test` of this branch alone (rewrite and the fix): default and total times, so rewrite isn't slower. Warm full lab at cff05e15: default 11m51s, total 11m51s, against rewrite's warm ~12m26s (faster; ruled met by the orchestrator).
- [x] (f) lab/README.md and lab/hostlock.go's docs say how slots are handed out.

## Notes
- TP-260 (done) built the queue this changes: tickets in the lock directory's `slot-queue/`, flock'd by their waiters, numbered in arrival order.
- How it works now (lab/hostlock.go, `slotClass` and the `slotQueue` doc; lab/README.md, "A cap on labs"): a long-stream waiter's ticket is named `…-long.wait`, any other `…-default.wait` (waiters outside a stream included). A default waiter watches only the default ticket just ahead of its own; a long waiter watches the long ticket just ahead of its own, else the newest default ticket. A long waiter whose turn it is lists `slot-queue/` on every poll (names and modification times only) and, on seeing a fresh default ticket, scans under the queue lock (which clears dead ones) and goes behind it. Price: a default waiter that joins in the instant between that listing and the long head's slot attempt can lose that one slot; long waiters wait as long as default waiters keep coming. Runs of code from before this change (untagged `….wait` tickets; their waiters watch the nearest older live ticket of any kind and don't look again while it lives) share the queue without deadlock: their tickets raise the next sequence and are cleared when dead, but no waiter of this code waits behind one, so an older run's waiter waits behind every older tagged ticket and a newer run's labs can take slots ahead of it. Reading them as default deadlocked (R1.1). Why no wait goes round: the `slotQueue` doc.
- Acceptance evidence: (a) TestDefaultStreamTakesFreedSlotsFirst (six waiters, half child processes in their own stream, half in this process: long-0, long-1, default-2, long-3, default-4, default-5 queue behind a held slot; slots go default-2, default-4, default-5, long-0, long-1, long-3) and TestLongWaiterGivesWayToDefaultThatJoinsLater (a long waiter already the head, heartbeats 10 s apart, leaves a freed slot alone for 1 s while a default ticket is queued behind it, then takes it once that waiter dies). (b) the first test: arrival order within each stream, and the long waiters get the slot once no default one is left. (c) TestKilledWaiterLeavesNoGap now runs each pair of killed/behind streams (a kill while queued and one while holding the slot), TestDeadTicketIsRemoved each pair of dead ticket/waiter streams (one dead ticket older and one newer than the waiter, the wait bounded to half the stale limit); a dead ticket of either stream is cleared and blocks no one. (f) the docs above.
- Measurements (full `make lab-test` runs on one quiet runner, no other lab containers, `THINKPOL_LAB_TIMELINE` set; times from each run's own lines; "the matrix's first slot wait" is the slot wait of the default stream's first censor matrix labs, from the timeline's `slot-wait` and `pool-take` lines):

  | run | commit | default | long | total | exit | matrix's first slot wait |
  |---|---|---|---|---|---|---|
  | before: tp-080-path-liveness, 3 long tests at once (2026-11-23) | aec08949 | 15m24s | 13m55s | 15m24s | over budget (3) | 2m16.6s, then 2m13s, 2m10s, 2m6.7s (four matrix labs) |
  | (d) tp-080-path-liveness + this branch, run 1 (cold) | 0bafda95 | 17m28s | 18m55s | 18m56s | failed | 1m50.7s, 1m58.3s |
  | (d) tp-080-path-liveness + this branch, run 2 | 0bafda95 | 13m6s | 14m4s | 14m4s | passed | 51s, 1m25.6s |
  | (e) this branch alone (rewrite d884a4e8 + the fix, cold) | a96a08a1 | 15m3s | 4m12s | 15m3s | over budget by 3 s | 2m35.8s, then 59–81 s |
  | (e) r1 fix, run 1 (cold: lab/ changed) | cff05e15 | 16m6s | 3m33s | 16m6s | failed (TestRealityPrototype) and over budget | 1m20.4s, 1m26.3s, 53.2s, 2m22.9s, 3m4.2s |
  | (e) r1 fix, run 2 (warm, right after run 1) | cff05e15 | 11m51s | 2m59s | 11m51s | passed (0) | 0s, 0s, 45.4s, 52.7s, 1m1.9s |

  0bafda95 is the throwaway branch `tp-287-measure-080`: origin/tp-080-path-liveness with this branch merged in (lab/README.md's conflict resolved keeping both sides), pushed only to measure, not for merging. Run 1 was cold: the change to `lab/` invalidates the harness phase's stamp and the node cache of every package that imports `lab`, so the harness phase ran (846 s) and 34 of 46 node packages ran in labs (summed slot wait 22m19s), against 1 package and no harness phase in the before-run. It failed once in the long stream: TestCensorMatrix/https_(control)'s snapshot (`tar … exit -1` on all four nodes) under that load, a load flake, so it was run again, warm: run 2 is the like-for-like comparison with the before-run, default stream 2m18s shorter and within budget, the matrix's first labs waiting 51 s instead of 2m16.6s. The long stream's own matrix lab (https (control)) waited longer than before (4m37s, was 3m1.8s): it gives way, as meant, and the long stream took 9 s longer than before (14m4s, was 13m55s), still 80 s inside the before-run's total.
  (e) was cold as well (harness phase ran, 386 s; 15 of 46 node packages ran, summed node slot wait 14m47s), so it isn't comparable with rewrite's warm ~12m26s: its 3 s over budget came from the default stream's own work, the long stream holding only its 2 labs for 4m12s. Whether rewrite with this change is as fast as rewrite warm is not measured here; the next warm full lab on rewrite after the merge shows it.
  (e) after the r1 fix: two full labs of cff05e15 back to back on a quiet runner (no other lab containers). Run 1 was cold (harness phase ran; 30 node packages ran in labs, summed node slot wait 15m4s) and failed in the default stream's `lab/` phase: TestRealityPrototype (`lab/prototypes/reality`), `xray 172.16.101.3:443 not answering` within 30 s under the cold run's load, a test this ticket doesn't touch. Run 2, warm (no harness phase, 46 of 46 node packages cached), passed: default stream 11m51s against rewrite's warm ~12m26s, 35 s faster. The box asks for rewrite's ±30 s; 35 s faster is just outside that band on the fast side; the box's intent is "rewrite isn't slower", so the orchestrator ruled it met.

## Review findings
- [x] R1.1 (blocker) Old and new code deadlock each other on a shared runner: code from before this change (TP-260's queue) watches the nearest older live ticket of any kind and never rescans while it lives, and this code reads an untagged ticket as default, with a long head watching the newest fresh default ticket. A new long head L (ticket 5) and an older run's waiter O (6, untagged) watch each other, both refresh, nobody tries a slot; every later waiter joins the cycle until the 45-min slot wait or LAB_TIMEOUT. Tag both classes (`-default.wait`, `-long.wait`), order by tagged tickets only (untagged ones still raise the sequence and are removed when dead), write why no cycle is left in the slotQueue doc; regression test (a long head, a fresh locked untagged ticket newer than its own, the slot freed: it takes the slot within a few polls), mutation: untagged counted as default; fix the Note on older runs.
- [x] R1.2 Box (e) is ticked without its evidence: the run was cold and 3 s over. Untick; measure two full labs of the final head back to back, the second warm; tick only if its default stream is about rewrite's warm ~12m26s (±30 s).
- [x] R1.3 streamSlotClass parses THINKPOL_LAB_STREAM itself while lab/stream.go's Stream already reads and validates it: reuse it.
- [x] R1.4 hostlock_test.go's `time.Sleep(5 * timing.poll)` in TestLongWaiterGivesWayToDefaultThatJoinsLater: wait for the condition instead (the long waiter has become the head).
- [x] R1.5 Docs: long waiters can starve while other runs' default streams keep coming; "the default stream ends first" holds only within one run. Say so in lab/README.md ("Streams", "A cap on labs") and the hostlock doc; no aging, LAB_TIMEOUT bounds it.
- [x] R1.6 A fresh default ticket that can't be locked makes a long head scan and warn on stderr every poll (~100 ms): warn at most once a heartbeat.

## Log
- 2026-11-26 created in backlog (lab speed: tp-080-path-liveness over budget)
- 2026-11-26 backlog → in-progress, owner: agent-tp-287
- 2026-11-26 lab/hostlock.go: slot waiters carry their stream's class in the ticket name (`-long.wait`); a freed slot goes to the oldest default waiter, else to the oldest long one; a long head lists the queue every poll for a default ticket that joined later. Tests in lab/hostlock_test.go; lab/README.md ("Streams", "A cap on labs") updated
- 2026-11-26 mutations, each failing its test: plain FIFO, the class ignored in scans and no look for default tickets (TestDefaultStreamTakesFreedSlotsFirst, TestLongWaiterGivesWayToDefaultThatJoinsLater); a long head that never looks for default tickets that joined after it (TestLongWaiterGivesWayToDefaultThatJoinsLater, and TestDefaultStreamTakesFreedSlotsFirst); a long waiter that doesn't scan for default tickets (both); long tickets not tagged (TestDefaultStreamTakesFreedSlotsFirst deadlocks to the timeout); a dead default ticket counted as live (TestKilledWaiterLeavesNoGap and TestDeadTicketIsRemoved, the default-ticket cases); dead tickets kept (both tests, every case)
- 2026-11-26 runs: the queue tests -race -count=3 green; make lint and make test green at a96a08a1; full labs: (d) on the throwaway tp-287-measure-080 at 0bafda95 twice (run 1 cold, failed on a load flake in the long stream; run 2 passed, default 13m6s, total 14m4s); (e) on a96a08a1, tests passed, default 15m3s, over budget by 3 s, cold (harness phase and 15 node packages run); ./lab's untagged tests passed in a lab node in (e)'s node phase. Numbers in Notes
- 2026-11-26 not verified: rewrite with this change on warm caches (e was cold); the race where a default waiter joins between a long head's listing and its slot attempt is not tested. The throwaway branch tp-287-measure-080 stays on origin until the orchestrator removes it
- 2026-11-26 in-progress → review
- 2026-11-26 review → has-errors: R1.1–R1.6 (review r1)
- 2026-11-26 has-errors → in-progress, owner: agent-tp-287
- 2026-11-26 R1.1: ticket classes both tagged (`-default.wait`, `-long.wait`); untagged tickets (code from before the classes) raise the sequence and are removed when dead but are in no waiter's way (lab/hostlock.go `slotQueueTag`, `ticketClass`; why no wait goes round: the `slotQueue` doc). Regression test TestLongWaiterPassesOlderRunsTicket (a long head, a fresh locked untagged ticket queued behind it, the slot freed: the head takes it within 25 polls); mutation: untagged tickets counted as default (`ticketClass` returning slotDefault for them) → the test fails ("left a freed slot alone for an older run's waiter"). TestDeadTicketIsRemoved now covers dead untagged tickets too
- 2026-11-26 R1.3 streamSlotClass reads lab.Stream; R1.4 TestLongWaiterGivesWayToDefaultThatJoinsLater waits on a head hook (`slotHeadHook`) instead of sleeping; R1.5 lab/README.md ("Streams", "A cap on labs") and the slotQueue doc say long waiters can wait as long as other runs' default streams keep coming, bounded by LAB_TIMEOUT, no aging; R1.6 a skipped ticket's warning comes at most once a heartbeat per waiter
- 2026-11-26 runs at cff05e15: make lint 0, make test 0; go test ./lab -run 'Slot|Waiter|Ticket|Queue' -count=5 ok (no lab needed: the queue tests run on the host); full labs back to back: run 1 cold, failed (TestRealityPrototype, xray not answering within 30 s under load; untouched by this ticket) and over budget (default 16m6s, long 3m33s); run 2 warm passed, default 11m51s, long 2m59s, total 11m51s. Numbers in Notes
- 2026-11-26 (e) left open: run 2's default stream is 35 s faster than rewrite's warm ~12m26s, just outside the ±30 s band asked for; for the orchestrator to judge
- 2026-11-26 in-progress → review
- 2026-11-26 (e) ticked, ruled met by the orchestrator: the warm full lab at cff05e15 ran the default stream in 11m51s against rewrite's warm ~12m26s (faster, outside the ±30 s band only on the fast side); the cold run before it failed on TestRealityPrototype (xray not answering on :443 within 30 s under the cold load), a test this ticket doesn't touch
- 2026-11-26 final review nits: lab/hostlock_test.go `fakeTicketOf` creates and locks its ticket under slot-queue.lock held exclusively, as a real ticket is, so no scan meets it unlocked and removes it as dead; new TestWaiterJoiningBehindOlderRunsTicket (long and default subtests: the waiter joins after a fresh, locked untagged ticket, heartbeats 60 ms so the head scans again several times, then takes the freed slot within 25 polls). Mutations, each restored: (a) a long head's default scan also matching untagged tickets, `defaultMayWait` unchanged → the long subtest fails; (b) a default waiter waiting on an older live untagged ticket (`scan` matching untagged for a default waiter) → the default subtest fails
- 2026-11-26 runs at 5febcd1e: make lint 0 (the first try failed only in govulncheck fetching its database, a network timeout; the retry passed), make test 0, go test ./lab -run 'Slot|Waiter|Ticket|Queue' -count=10 ok; no full lab (test-only change)
