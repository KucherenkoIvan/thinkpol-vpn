---
id: TP-268
title: "The lab's longest tests start first; waiting for a pooled lab doesn't hold a parallel place"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-268"
branch: "tp-268-critical-path"
---

## Goal
In TP-261's full labs, TestKillSwitchUnderSystemd (four parallel parts) only starts ~8 minutes in, because tests waiting for a pooled lab occupy `-parallel` places, so it ends with the censor matrix and both sit on the critical path; the warm full lab's default stream had 3 s to spare (14m57s of 15m). The longest tests should start at the beginning, and a test waiting for a pooled lab should not keep another test from starting.

## Scope
- From the budget report and the timeline of the last full labs, find the critical path: which tests end last, and when they started.
- Make the longest tests (the matrix rows, the kill-switch parts, others the report names) start at the beginning. Go runs parallel tests in source order after the serial ones: order the declarations, or have long tests call t.Parallel first; check what actually controls start order.
- Make a test waiting for a pooled lab not hold a `-parallel` place (acquiring before t.Parallel serializes; raising `-parallel` above the slot cap may do, since slots and pools bound the real concurrency): reason it out and measure.
- Keep every test's claims.

## Out of scope
- Fewer container starts, faster lab starts, node-phase caching (TP-242, TP-243, the node-phase pooling ticket).

## Acceptance
- [x] Critical path before/after from the timeline (which tests end last, when they started), in Notes. Before: the matrix's last row (took its lab 782 s, ended 931 s) and the kill switch (started ~290 s, ended 738 s); after: both done first in every run, the node phase (cold) or a pooled test behind its own late lab start (warm) last (Notes, "Runs"). Fix round A/B on bfe277f0 against rewrite 6832b93c (Notes, "Fix round"): on rewrite the matrix's last row took its lab at 782 s and 642 s, the matrix ended last (1010 s, 793 s), the kill switch started at 290 s and 517 s; on the branch the kill switch ran 42–198 s and the matrix, still the last test, ended at 714 s and 711 s.
- [x] Warm full lab default stream before/after, in Notes (target: ≥ 2 min faster). First round not met (16m9s before; 18m45s, 20m6s and 25m35s after, each under another session's labs). Fix round A/B, warm, alternating, quiet at each start: rewrite 17m29s and 13m51s (median 15m40s), branch 13m10s and 12m59s (median 13m4.5s): 2m35.5s faster (Notes, "Fix round"; the spread caveat there).
- [x] No new flakes: the full lab green twice. Four full labs on d39cbd58: every test passed, no lab retired (all over budget, as the baselines). Fix round, bfe277f0: two warm full labs passed within budget (exit 0), plus the cold throwaway (passed, over budget).

## Notes
- Baseline: TP-261's final head 3b356c7c, full lab twice: 897 s (default 14m57s) and 713 s (default 11m53s).

### What controls start order (go test 1.26, testing.go)
- A parallel test waits for one of `-parallel`'s places when it resumes (`waitParallel`) and holds it to its end, also while it waits in a pool's queue or for a lab slot. With `-parallel` = LAB_SLOTS (12), tests queued on pools held most places, and TestCensorMatrix (results_test.go) and TestKillSwitchUnderSystemd (killswitch_test.go), late in source order, got theirs minutes in; their subtests then took places one by one.
- Parallel tests resume all at once once every test's serial part has run; which reaches the slot queue first is a race. A test's serial part (before `t.Parallel`) runs in source order before any parallel test does. The slot queue is first come first served across processes.

### What changed
- `make lab-test`'s `lab/` phases run every test at once (`LAB_TEST_PARALLEL` = 256): waiting costs a goroutine; slots and pools bound the labs.
- `lab.StartFirst(t, topo, n)` / `pool.StartFirst(t, n)`, in place of `t.Parallel`: count the test's lab starts in during the serial part, call `t.Parallel`, start them at resume; every other lab start of the process joins the slot queue only after those joined (`firstStarts`, per lock directory; a start waiting on first starts that never began fails after 30 s instead of hanging). Used by the censor matrix (its stream's row labs, up to the censor pool's 5) and the kill switch (its 4 parts). Only in a stream: a run by hand may run only some subtests.
- `pool.AcquireInOrder(t, rank)`: the matrix's rows take the censor pool's labs in `matrixLabs` order (longest first) instead of racing. A pool counts labs started first that are still coming, so a test waits for one instead of starting another (the first after-run's long stream started 4 labs for 2 tests).
- A process stands at most 2 lab starts in the slot queue at once (`slotQueueShare`), first starts aside: with every `lab/` test at once and no share, the `lab/` phase queued ~23 starts at once and a cold node phase waited behind all of them (after-run 1, 9cbc858c: default stream 25m10s; node phase summed slot wait 55m → 3h31m; firewall's package waited 18m for a slot).
- The timeline (`THINKPOL_LAB_TIMELINE`) gets each `lab/` test's start, resume after `t.Parallel` and end, with its stream (`test-run`, `test-cont`, `test-pass`), from `labctl testjson`.

### Runs (`make lab-test` with the timeline; another session's labs on the same runner during these runs)
| Run | Commit | Node phase / harness | Default stream | Matrix (default stream) | Kill switch |
|---|---|---|---|---|---|
| base1 | 32ddb7c5 (rewrite + the timeline lines) | 24 packages in labs / run | 18m10s, over budget | parent resumed 67 s, rows resumed up to 761 s, last row took its lab 864 s, ended 1045 s | parts resumed 707–761 s, ended 872 s |
| base2 | 32ddb7c5 | cached / cached | 16m9s, over budget | parent resumed 274 s, rows resumed 305–702 s, last row (wireguard) took its lab 782 s, ended 931 s | parts resumed 284–304 s, slot waits 4m20–4m40, ended 738 s |
| final1 | d39cbd58 | 24 in labs / run | 16m43s, over budget | first lab 184 s, rows ended 730 s | slot waits from 71 s, ended 325 s |
| final2 | d39cbd58 | cached / cached | 25m35s, over budget | first lab 418 s, ended 1048 s | ended 601 s |
| final3 | d39cbd58 | cached / cached | 18m45s, over budget | first lab 131 s, ended 686 s | ended 209 s |
| final4 | d39cbd58 | cached / cached | 20m6s, over budget | first lab 298 s, ended 957 s | ended 471 s |

All tests passed in every run (no lab retired outside the harness's deliberate case); every run was over the 15m budget, the baselines too.

**Critical path before** (base1, base2): the censor matrix's last rows and the kill switch: the matrix's parent got its `-parallel` place 274 s in (base2), its rows trickled in as places freed, the last one took its lab at 782 s and ended at 931 s; the kill switch's parts started at ~290 s and waited 4m20–4m40 for slots, ending at 738 s.

**Critical path after**: the matrix and the kill switch are off it in every run on d39cbd58 (matrix done at 686–1048 s, kill switch at 209–601 s, both started first). It is now the node phase when cold (final1: firewall's package waited 9m35s for a slot, as in base1, but the run was 1m27s faster) and, warm, pooled tests that committed to a lab start of their own: in final3 TestEgressThroughAnExit ended last (1099 s): the standard pool had room, so it started a second lab, whose slot wait took 14m25s, while the pool's first lab served three tests and went idle at ~17 min. In final2 all 12 slots were held by the other session's labs for the first 4.5 minutes (even the first starts waited 4m31–7m52).

**Warm default stream: not faster** (16m9s → 18m45s, 20m6s, 25m35s), under the other session's labs on the same slots: that session runs code without the per-process queue share, so its processes queued every start while this run stood two in line. A quiet runner was never available for a clean comparison (the other session started a lab during each final run).

### Fix round (2026-11-22)
- **Fix**: a pooled test whose own lab start still waits for its slot takes a lab that comes back meanwhile, once no test waits in line (a waiting test has no start coming, so it goes first): `Pool.startOrTake`, `Pool.handOn` (lab/pool.go). The start it no longer needs leaves the slot queue and the process's share of it (`withSlotWaitStop`, `errSlotWaitStopped` in lab/lab.go's `waitForSlot`) and is counted out; one that holds its slot already goes on and its lab joins the pool (`Pool.putBack`), torn down if the pool has closed, which waits for it (`Pool.down`). The node pool (TP-269) gets the same through `Pool.acquire`.
- **Ordering kept**: after TP-269 (node-phase reuse) the `lab/` phase's order still decides the default stream: on rewrite the censor matrix ends last and the kill switch starts 5–9 minutes in; on the branch both start at once.
- **A/B** (`make lab-test`, alternating, warm; before each run no other session's lab containers and no other docker lock holder; throwaways first: branch 16m13s, cold after the image rebuild; rewrite 19m32s, under other sessions' labs; neither counted):

| Run | Commit | Wall | Default | Long | Exit | Slot wait median / max | Critical path |
|---|---|---|---|---|---|---|---|
| A1 rewrite | 6832b93c | 1049 s | 17m29s, over budget | 3m27s | 3 (tests passed) | 0.3 s / 112 s | matrix last row (wireguard) took its lab 782 s, matrix ended last ~1010 s; kill switch 290–490 s |
| B1 branch | bfe277f0 | 791 s | 13m10s | 3m8s | 0 | 48 s / 562 s | matrix resumed 42 s, last row took its lab 598 s, ended last 714 s; kill switch 49–198 s |
| A2 rewrite | 6832b93c | 832 s | 13m51s | 3m14s | 0 | 0.0 s / 86 s | matrix last row (wireguard) 642 s, ended last ~793 s; kill switch 517–688 s |
| B2 branch | bfe277f0 | 778 s | 12m59s | 3m16s | 0 | 51 s / 575 s | matrix resumed 37 s, last row took its lab 606 s, ended last 711 s; kill switch 42–176 s |

All four: every test passed, node phase 39 of 40 packages cached. During A1 and A2 no other session's labs or docker lock showed (at the start and at a check mid-run); during B1 and B2 another session's labs started 5–7 minutes in, so the branch's numbers carry load the rewrite's don't.
- **Verdict**: default stream median 15m40s on rewrite, 13m4.5s on the branch: 2m35.5s faster, green both times, so the ticket goes to review. Caveat: the rewrite runs spread 3m38s (17m29s, 13m51s); against A2 alone the branch is 41–52 s faster. The branch's two runs agree within 11 s.
- Slot waits read higher on the branch: there a start's wait includes the time it stands outside the queue, behind the first starts and the process's share (slotQueueShare). The longest are fresh starts (TestServiceUninstallAfterAServerCrash, 9m22s) that end well before the matrix.
- Not seen in the A/B: whether a start ever gave way to a lab that came back. The timeline has no line for it; the unit tests show the mechanism.

### Next steps (not done here)
- Measure again once every runner's code has the queue share (other branches merged), on a quiet runner; consider a larger share if the default stream still waits behind other phases.

## Log
- 2026-11-19 created in backlog (owner: do 1-2)
- 2026-11-19 backlog → in-progress, owner: agent-tp-268
- 2026-11-19 labctl testjson notes each lab/ test's start, resume and end, with its stream, in the timeline (lab/streamtime.go FilterTestJSON, lab/timeline.go noteTest; the Makefile gives labctl testjson the stream); baseline full labs on 32ddb7c5 (rewrite + those lines): 18m10s cold, 16m9s warm, tests passed, over budget
- 2026-11-19 built: LAB_TEST_PARALLEL (Makefile), lab.StartFirst/FirstLabs.Take and Pool.StartFirst (lab/startfirst.go), the first-start gate per lock directory (firstStarts, lab/hostlock.go acquireHostSlot), Pool.AcquireInOrder and the pool's labs coming (lab/pool.go), the matrix (lab/results_test.go, lab/matrixreset_test.go) and the kill switch (lab/killswitch_test.go) start first; first design (starts in the serial part) dropped: serial unit tests set TMPDIR and the slot cap, which a start beside them would read
- 2026-11-19 after-run 1 (9cbc858c, cold): 25m10s, node phase summed slot wait 55m → 3h31m behind the lab/ phase's ~23 queued starts: added the per-process slot queue share (slotQueueShare = 2; lab/hostlock_test.go's queue tests turn it off, their in-process waiters stand for other runs); the long stream's pool started 4 labs for 2 tests: fixed (Pool.coming)
- 2026-11-19 mutations (each restored after, on the Mac): noteTest without the depth filter → TestFilterTestJSONTimeline fails; stream dropped from the lines → fails; slotOrder never waits → TestSlotWaitsBehindFirstStarts fails; no joinedSlotQueue → fails; no grace case → fails; ranks ignored in take → TestPoolTakeInOrder fails; take ignores coming labs → TestPoolWaitsForLabsComing fails; no share → TestSlotQueueShare fails; first starts counted in the share → fails. Not mutation-checked: StartFirst's and Pool.StartFirst's launch at resume (need Docker; the full labs' timelines show their slot waits first: kill switch's 4 at 45–75 s)
- 2026-11-19 runs on d39cbd58: make lint, make test passed; four full labs, all tests passed, all over budget: 16m43s (cold node phase, harness run), 25m35s, 18m45s, 20m6s (warm), another session's labs on the same slots during each; critical path before/after in Notes; the warm target (≥ 2 min faster) not met (Notes: pooled tests behind their own late lab starts, the share against a run without it)
- 2026-11-19 out of scope: TestGotestRunsNodelessPackagesOnTheHost (lab/labctl) fails on a Mac (go test on the host finds no package under the temporary directory), passes on Linux; a pool test that started its own lab waits for its slot even when its pool's other lab comes back idle (final3: 14m25s, Notes "Next steps")
- 2026-11-19 in-progress → review
- 2026-11-22 review → in-progress, owner: agent-tp-268 (fix round: a pooled test behind its own lab start, then a quiet A/B)
- 2026-11-22 merged origin/rewrite (TP-269's node pool) at 3fdaf8a0: lab/pool.go keeps TP-269's acquire/adopt split, takers and close, and TP-268's ranks and labs coming; adopt counts a failed start out, so Pool.came(nil) only takes it off the labs coming and lets the waiters beyond them start one
- 2026-11-22 fix: a pooled test whose own lab start waits for its slot takes a lab that comes back meanwhile, once no test waits in take (Pool.startOrTake, Pool.handOn: waiters first, then starters, lab/pool.go); the start leaves the slot queue and the process's share of it (withSlotWaitStop, errSlotWaitStopped, lab/lab.go waitForSlot) and is counted out, or, holding its slot already, goes on and its lab joins the pool (Pool.putBack; in a closed pool it is torn down, and closing waits for it: Pool.down); the node pool's goTest reads the start's slot wait only once it is done (lab/gotestpool.go); README "Slots and waiting", lab/doc.go
- 2026-11-22 tests: TestPoolStartGivesWayToALabThatCameBack (lab/poolslot_test.go, a real one-slot lock directory), TestPoolTearsDownAStartNobodyNeedsAtClose, TestPoolWaitsForLabsComing extended (lab/pool_test.go); mutations (each restored after, on the Mac): handOn never gives a lab to a starter → the starting test gets no lab; starters before waiters → the waiting test gets none; stop never closed → the start still waits for its slot; waitForSlot ignores the stop → same; came(nil) without letting waiters start → the waiter waits for a lab no longer coming; the abandoned start not counted in Pool.down → the pool closes while a lab of its is still starting; putBack in a closed pool keeps the lab → torn down 0 times, 2 labs 1 idle
- 2026-11-22 on d31d26af: make lint, make test passed; go test -race ./lab/ -run 'Pool|Slot|First' -count=10 passed
- 2026-11-22 merged origin/rewrite again (TP-275's nginx pin) at bfe277f0; A/B full labs, alternating, quiet at each start (throwaways first: branch 16m13s cold, rewrite 19m32s under other sessions' labs): rewrite 6832b93c 17m29s (exit 3, passed) and 13m51s (exit 0); branch bfe277f0 13m10s and 12m59s (exit 0, another session's labs started 5–7 minutes into each); default stream median 15m40s → 13m4.5s, 2m35.5s faster (Notes "Fix round", with the rewrite runs' spread)
- 2026-11-22 not verified: that a start gave way to a lab that came back in the full labs (no timeline line for it; the unit tests cover the mechanism); targeted lab-gotest runs not done separately: the four full labs on bfe277f0 run every lab/ test and the node phase
- 2026-11-22 on bfe277f0: make lint, make test passed; lab commit bfe277f0
- 2026-11-22 in-progress → review
