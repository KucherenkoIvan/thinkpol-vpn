---
id: TP-265
title: "The node phase reports a package's slot wait apart from its run time"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-266"
branch: "tp-266-host-packages"
---

## Goal
A package's time in the node phase (`GoTestResult.Elapsed`, lab/gotest.go `inLab`) starts when its lab starts, so it includes the wait for a lab slot, `docker compose up` and teardown. In TP-263's measurement packettest looked 8.5 minutes slow while its tests take 0 s. Lab-speed work needs to see which part of a package's time is its own.

## Scope
- Time the slot wait, the lab start, the tests and the teardown of each package separately.
- Show the four in the node phase's output and in the budget report.

## Acceptance
- [x] Node-phase lines and the budget report show slot wait, lab start, tests and teardown separately (test).

## Notes
**What changed.** `waitForSlot` hands its measured wait (the same from/to as the timeline's `slot-wait` line) to the start's clock when asked (`startClock.slotWait`, lab/lab.go); `goTestFresh` (lab/gotest.go) times the rest: lab start (everything in `up` but the slot wait: a leftover lab's removal, compose up, sealing), tests (the test binary and reading its test log back) and teardown (`Down`), as `GoTestResult.Phases` (`lab.LabPhases`). Each package run in a lab ends its block with one line, e.g. from the full lab below:

`lab gotest .../internal/dataplane/firewall: took 9m26.2s (slot wait 6m36.6s, lab start 42.5s, tests 1m45.8s, teardown 21.3s)`

The times file (`-times`, node.times) carries the four as a third tab-separated field; `labctl budget` prints them beside each node package on the over-budget list and, in every report, the node phase's labs summed:

`node phase, 22 packages in labs, summed: slot wait 1h18m58.6s, lab start 21m18.2s, tests 11m19.7s, teardown 8m13s`

The summed slot wait matches the timeline: the cold node-phase run on b886094f summed 3280 s from the lines and 3280 s from THINKPOL_LAB_TIMELINE's slot-wait lines. Packages run on the host (TP-266) show `took <t> (on the host)`.

**Round 1: the run's own queue.** A package waiting for one of its own run's labs (`-p`, `LAB_P`'s labs: GoTestConcurrency.Labs; with `-perf`, for every build) waited in neither Elapsed nor the slot wait. `goTestGates.run` now hands `labRun` when the package began to queue, Elapsed counts from then, and LabPhases has a fifth phase, `queue`, first: `lab gotest …/internal/agent: took 16m33.4s (queue 5m39.2s, slot wait 8m59.3s, lab start 28s, tests 1m10.2s, teardown 16.6s)` (cold node phase, 275ed9d7). The times file carries five fields, and the budget's summed line starts with the queue. In that run 11 of 23 labs queued 3m38s to 5m39s behind the run's own 12, 3238 s summed against 8715 s of slot wait.

**What it shows.** In that full lab, slot waits are 66% of the node packages' lab time and their tests 9%: nsthread took 14m30s for 0.3 s of tests, router 11m39s for 0.6 s. The node phase's speed is the slots' and the lab start's, not the tests'.

## Review findings
- [x] R1.6 (should-fix) the wait for the run's own lab gate (takeGate before inLab's start, lab/gotest.go) is in neither Elapsed nor SlotWait, so a node phase queued on its own gate shows "slot wait 0s": time it (in SlotWait or a "queue" column); a test that drops `clock.slotWait = &slotWait` must fail.

## Log
- 2026-11-19 created in backlog (TP-263)
- 2026-11-19 backlog → in-progress, owner: agent-tp-266
- 2026-11-19 implemented on tp-266-host-packages (with TP-266): LabPhases, startClock.slotWait, node-phase time lines, phases in the times file and the budget report; TestLabPhases, TestLabTimeLine, TestWaitForSlotTimesTheWait, TestTestTimesRoundTripPhases, TestCheckBudgetPhases, TestWriteGotestTimesKeepsPhases
- 2026-11-19 mutations, each killed: M8 lab start keeps the slot wait (TestLabPhases); M9 the slot wait not noted (TestWaitForSlotTimesTheWait); M10 phases not written to the times file; M11 the budget's summed line dropped; M12 labctl drops the phases from -times
- 2026-11-19 full make lab-test on 7be89020: tests passed, over budget 23m53s (as on rewrite); node-phase lines and the budget report show the four phases (Notes)
- 2026-11-19 in-progress → review
- 2026-11-19 review → has-errors
- 2026-11-19 review round 1: fix R1.6
- 2026-11-19 R1.6 fixed: LabPhases.Queue (lab/gotest.go), goTestGates.run passes the time a package began to queue for its lab, inLab's Elapsed counts from it, labTimer wires the slot wait into the start's clock; the times file and the budget carry the queue; TestGoTestGatesTimeTheLabQueue, TestLabTimerTimesTheSlotWait, TestLabPhases, TestTestTimesRoundTripPhases, TestCheckBudgetPhases
- 2026-11-19 mutations, each killed: M20a the start's clock without `slotWait` (TestLabTimerTimesTheSlotWait), M20b the queue timed from the lab token (TestGoTestGatesTimeTheLabQueue), M20c no queue phase (TestLabPhases), M20d the queue left out of the times file (TestTestTimesRoundTripPhases)
- 2026-11-19 runs: see TP-266's Log (same branch): cold node phase on 275ed9d7 shows the queue column; full make lab-test on 152d52ed passed, over budget only
- 2026-11-19 has-errors → review
- 2026-11-19 review → done (merged)
