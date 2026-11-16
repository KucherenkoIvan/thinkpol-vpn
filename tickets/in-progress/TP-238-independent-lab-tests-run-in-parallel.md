---
id: TP-238
title: "Independent lab tests run in parallel; tests that must run alone get their own stream"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: [TP-200]
refs: []
owner: "agent-tp-238"
branch: "tp-238-parallel-lab-tests"
---

## Goal
The `lab/` package runs its tests one after another, and the teardown tests that can't share the host run first, adding ~14.5 min before anything parallel.

The owner (2026-11-16): a full lab must take at most ~15 minutes on the remote runner; waits only where no watcher can tell, otherwise a sped-up clock; long-wait tests in a separate stream that never blocks others; everything that can run in parallel must. Measured on the remote runner (2026-11-16): the `lab/` package alone took ~46 min; the host-wide subnet allocation lock is held for each lab's whole `docker compose up --wait` (10–45 s per lab), so lab starts are serialized across every run (~92% busy); non-parallel teardown tests add a ~14.5-minute serial prefix before parallel tests resume.

## Scope
- The `lab/` tests that start labs without `t.Parallel()`, and the shared state that kept them serial.
- Lab names: two processes of one run never share a test's or package's lab.

## Out of scope
- labctl's subnet allocation and its lock (TP-229).
- The censor matrix's rhythm cells and the long-wait stream with its budget (TP-223, TP-239).
- Topologies, and how many containers a lab starts.

## Acceptance
- [x] Every `lab/` test that doesn't need the host to itself runs in parallel with the others (list in Notes which can't, and why).
- [x] Tests that truly must run alone run in their own stream, alongside the parallel tests instead of in front of them.
- [ ] No new flakes: the changed tests pass 3 full labs in a row on the remote runner.
- [ ] The `lab/` package's wall time before and after, in Notes.

## Notes
Depends on TP-200 (it changes how lab tests start nodes, in many of the same files): build on it.

**What kept tests serial.** Go runs a package's non-parallel top-level tests first and resumes the parallel ones only after all of them end. Every lab-starting test in `lab/` was parallel except `TestLabsBelongToTheirCheckout` and `TestDownRunRemovesOnlyItsRun` (teardown_lab_test.go), which set `THINKPOL_LAB_PROJECT` with `t.Setenv` (Go refuses that in a parallel test, and it would leak into every other test's lab names). Each starts labs, so their lab starts, waiting on the slot cap and the subnet lock behind other runs' labs, sat in front of every parallel test (measured from 21 s to 869 s, depending on what else the runner was doing). They now take the override as a parameter (`startAs`, `checkoutProject`, `downRun`) and run in parallel. The rest of the serial set is unit tests with no Docker (milliseconds, at most 0.6 s each); `TestAwaitJudgments` (1.4 s) and `TestStatusChecksFailWithoutTheirFact` are now parallel too.

**Run alone: none.** No `lab/` test needs the host to itself once the teardown tests stop changing the environment: each of them works on labs it names itself (a fresh run id, its own override, a temp checkout) and never removes another test's lab. The tests that do need the host alone are the performance gates, already their own target (`make lab-perf`, which waits for every other lab run). So there is no second stream to start beside the parallel set; `make lab-test` is unchanged.

**Per-process lab names.** `make lab-test` gives its phases one run id, and a retry or a shard of the same tests under that id would have reused a test's lab name and replaced the other process's lab. Test and gotest lab names now hash in an id of the process (`processID`) next to the package and test; the run id stays in the name, so `labctl down -run` still finds the run's labs. Name lengths are unchanged.

**Fixed waits left (for TP-239 or later).** None in the tests this ticket touched. Elsewhere in `lab/`: `killswitch_test.go` holds 45 s to see the direct destinations renewed past their 30 s timeout (a real timer: a candidate for a sped-up clock); `censor_prober_test.go` sleeps `judgedAfter` before reading the censor's log; short poll intervals (50 to 500 ms) in loops with deadlines in `censor_prober_test.go`, `netstate_test.go`, `nodestatus_test.go`, `results_test.go`, `gotest_unix_test.go`.

**Wall time of the `lab/` package** (`make lab-gotest PKG=./lab`, one run at a time from this ticket, other branches' labs on the runner as usual):

| Run | Commit | Wall time | Failures |
|---|---|---|---|
| before | rewrite e1efa92a | 3600 s, killed at the 60 min cap | 3 (the 10 min test limit); an earlier run on the same commit: 1 |
| after 1 | c7cf5d67 | 3600 s, killed at the cap | 12, all lab setups (subnet lock, slot cap, slow compose up) |
| after 2 | c7cf5d67 | 3600 s, killed at the cap | 13, all lab setups |
| after 3 | c7cf5d67 | 3600 s, killed at the cap | 11, all lab setups |
| after, with TP-229's branch merged in (not committed) | c7cf5d67 + c15ecac9 | 3600 s, killed at the cap with the censor matrix still running | 1: `TestBlobDistribution` (a blob missing on device-a, unrelated); no lab setup failed |

No run finished inside the cap, so there's no before/after number yet. Two things hold the package past it, and neither is this ticket's: the host-wide subnet lock held through each lab's whole `compose up` (TP-229), which with more tests in parallel only lengthens its queue (after runs 1 to 3); and the censor matrix (TP-239, TP-240), still running at the cut once TP-229's fix removed the setup failures. The serial prefix this ticket removes measured 170 s in the before run (82 s + 88 s) and 21 s in an earlier one.

**Not changed, for later.** The `lab/` phase runs `go test` with the default `-parallel` (GOMAXPROCS), below the lab slot cap (12); raising it may help only if lab starts aren't the bottleneck (Docker on the runner starts about 18 to 20 containers a minute whatever the parallelism).

## Log
- 2026-11-16 created in backlog (owner: lab fixes, top priority)
- 2026-11-16 backlog → in-progress, owner: agent-tp-238
- 2026-11-16 teardown tests take the project override as a parameter and run in parallel; test and gotest lab names hash in a per-process id; TestAwaitJudgments and TestStatusChecksFailWithoutTheirFact parallel (a55d0c1f). make lint and make test green on a55d0c1f
- 2026-11-16 mutation: dropping the process id from testProject's hash, then from goTestPackageProject's, each fails TestRunProjectNames ("process p2's ... process p1's is" the same name); restored
- 2026-11-16 baseline, make lab-gotest PKG=./lab on rewrite e1efa92a, runner loaded by two other branches' labs: killed at the 60 min cap (3600 s, exit 2), 3 tests failed at the 10 min in-node limit, 6 lab setups timed out on the subnet allocation lock; the serial prefix (TestLabsBelongToTheirCheckout 82 s, TestDownRunRemovesOnlyItsRun 88 s) ran before any parallel test. An earlier baseline on the same commit: also killed at 3600 s
- 2026-11-16 after, same command on c7cf5d67, two runs under the same load: both killed at the 60 min cap (exit 2), 12 and 13 failures, every one a lab setup that ran out of the start's 10 min deadline: waiting on the subnet allocation lock or the slot cap (TP-229's known issue), or in a `docker compose up` that slow Docker had not finished; the teardown tests now pause with the parallel set (=== PAUSE) instead of running in front of it
- 2026-11-16 after, run 3 on c7cf5d67, started with no other lab on the runner (others started during it): killed at the 60 min cap (exit 2), 11 failures, again all lab setups out of the start's 10 min deadline (10 on the subnet allocation lock, TestLabsBelongToTheirCheckout among them, 1 in a slow `docker compose up`). With every lab start holding the host-wide subnet lock through its whole `compose up`, more tests in parallel only lengthen that queue: this ticket's gain can't show, and its 3-green-runs box can't be met, until TP-229 lands
- 2026-11-17 measurement only: c7cf5d67 with origin/tp-229-subnet-lock-scope c15ecac9 merged in a scratch checkout (no commit): killed at the 60 min cap with the censor matrix still running, no lab setup failures, 1 failure (`TestBlobDistribution`: device-a's blob file missing; it passed in an earlier rewrite run: out of scope, for its owner)
- 2026-11-17 handoff: code done, boxes 1 and 2 ticked (re-read the diff); boxes 3 and 4 wait on TP-229 (lab setups time out on its lock under load) and on the censor matrix's length (TP-239/TP-240): no lab/ run can finish inside the 60 min cap until then. Next: once TP-229 is in rewrite, merge it, run make lab-gotest PKG=./lab three times and one full make lab-test, fill the table, move to review. No full make lab-test on this branch yet
