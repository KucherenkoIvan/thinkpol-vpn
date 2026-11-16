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
- [ ] Every `lab/` test that doesn't need the host to itself runs in parallel with the others (list in Notes which can't, and why).
- [ ] Tests that truly must run alone run in their own stream, alongside the parallel tests instead of in front of them.
- [ ] No new flakes: the changed tests pass 3 full labs in a row on the remote runner.
- [ ] The `lab/` package's wall time before and after, in Notes.

## Notes
Depends on TP-200 (it changes how lab tests start nodes, in many of the same files): build on it.

**What kept tests serial.** Go runs a package's non-parallel top-level tests first and resumes the parallel ones only after all of them end. Every lab-starting test in `lab/` was parallel except `TestLabsBelongToTheirCheckout` and `TestDownRunRemovesOnlyItsRun` (teardown_lab_test.go), which set `THINKPOL_LAB_PROJECT` with `t.Setenv` (Go refuses that in a parallel test, and it would leak into every other test's lab names). Each starts labs, so their lab starts, waiting on the slot cap and the subnet lock behind other runs' labs, sat in front of every parallel test (measured from 21 s to 869 s, depending on what else the runner was doing). They now take the override as a parameter (`startAs`, `checkoutProject`, `downRun`) and run in parallel. The rest of the serial set is unit tests with no Docker (milliseconds, at most 0.6 s each); `TestAwaitJudgments` (1.4 s) and `TestStatusChecksFailWithoutTheirFact` are now parallel too.

**Run alone: none.** No `lab/` test needs the host to itself once the teardown tests stop changing the environment: each of them works on labs it names itself (a fresh run id, its own override, a temp checkout) and never removes another test's lab. The tests that do need the host alone are the performance gates, already their own target (`make lab-perf`, which waits for every other lab run). So there is no second stream to start beside the parallel set; `make lab-test` is unchanged.

**Per-process lab names.** `make lab-test` gives its phases one run id, and a retry or a shard of the same tests under that id would have reused a test's lab name and replaced the other process's lab. Test and gotest lab names now hash in an id of the process (`processID`) next to the package and test; the run id stays in the name, so `labctl down -run` still finds the run's labs. Name lengths are unchanged.

**Fixed waits left (for TP-239 or later).** None in the tests this ticket touched. Elsewhere in `lab/`: `killswitch_test.go` holds 45 s to see the direct destinations renewed past their 30 s timeout (a real timer: a candidate for a sped-up clock); `censor_prober_test.go` sleeps `judgedAfter` before reading the censor's log; short poll intervals (50 to 500 ms) in loops with deadlines in `censor_prober_test.go`, `netstate_test.go`, `nodestatus_test.go`, `results_test.go`, `gotest_unix_test.go`.

**Not changed, for later.** The `lab/` phase runs `go test` with the default `-parallel` (GOMAXPROCS), below the lab slot cap (12); raising it may help only if lab starts aren't the bottleneck (Docker on the runner starts about 18 to 20 containers a minute whatever the parallelism).

## Log
- 2026-11-16 created in backlog (owner: lab fixes, top priority)
- 2026-11-16 backlog → in-progress, owner: agent-tp-238
