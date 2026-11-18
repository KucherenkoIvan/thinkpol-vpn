---
id: TP-241
title: "Lab waits become watchers or sped-up clocks"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: [TP-200]
refs: []
owner: "agent-tp-241"
branch: "tp-241-lab-watchers"
---

## Goal
Waits only where no watcher can see the result. The owner wants a full lab to take at most 15 minutes on the remote runner. Measured 2026-11-16: a clean full lab takes 2823 s, and the remote runner's Docker starts only ~18–20 containers a minute, while a run starts 836 containers: the censor matrix 574 of them in 90 labs, each cell in use only 5–30 s.

## Scope
- (a) Blocked-probe windows (`blockedWindow`, lab/results_test.go:947–954, 8 s per family) and log-absence polls (`pollLog`, lab/results_test.go:1274, 3 s each): censord writes a flushed-through watermark, and probes stop as soon as the verdict log shows the blocking verdict.
- (b) Reality's blocked cells: `realityUp` waits 60 s for `link up` even when the cell expects a block (lab/reality_matrix_test.go:72–84). Stop on the censor verdict.
- (c) Kill switch: `time.Sleep(45 s)` and 4 × 10 s re-apply ticks (lab/killswitch_test.go:357–381), plus firewall `DirectTimeout` (const 30 s, internal/dataplane/firewall/killswitch.go:77) in internal/dataplane/firewall/killswitch_linux_test.go:485–499. Make the timeout and tick injectable, or watch the nft set element's `expires` refresh.
- (d) dns 500-iteration loop (115 s): fewer iterations with the false-pass probability stated, or the file on tmpfs. The per-update cost of 0.23 s needs a look.
- (e) Prober settle windows (settleWithin 2 min, judgedAfter 1 s sleep): lab prober settings with shorter timeouts.
- Every `lab.Eventually` bound stays as it is; they poll at 200 ms and cost only when slow.

## Out of scope
- Fixed sleeps in unit tests outside the lab and in-node tests: TP-173.

## Acceptance
- [x] grep shows no `time.Sleep` ≥ 1 s in lab/ or in-node tests outside the long stream, each remaining one commented with why no watcher can see it.
- [ ] Matrix cells' median in-use ≤ 10 s. Evidence: the budget report.
- [ ] Kill-switch lab test in use ≤ 60 s.

## Notes
- Saving: ~10–12 min of summed lab in-use time: ~30 blocked cells × 10–16 s, 2 × 60 s reality, ~70 s kill switch, ~100 s dns, prober ~1–2 min. On the critical path after TP-240, ~1–2 min per matrix row.
- Overlaps TP-200 (waits on `status -json` instead of log greps, one node-start helper): same waits (`waitOutput` patterns) and files. Land TP-200 first, or do group (b) inside it.
- Related: TP-173 (fixed sleeps across all tests, milestone later).

## Log
- 2026-11-16 created in backlog (owner: lab fixes, top priority; from the lab-speed audit)
- 2026-11-18 backlog → in-progress, owner: agent-tp-241
- 2026-11-18 (a) censord writes a watermark line (`censor.EventWatermark`, the last queue packet id decided) at each flush after the queue moved; the matrix's verdict-log reads (`censorRun.caughtUp`) wait for it to reach the queue's id_sequence (bound 30 s, the failure shows both ids and censord's output) instead of the 3 s absence polls; a cell that should be blocked stops probing once the log shows its blocker's drop or reset (`probeBudget.blocked`), else after blockedWindow as before. (b) reality's blocked cells stop waiting for the link on the same verdict. (e) the prober's settle and judged read the caught-up log, the lab prober times out after 1 s. Commit 095259d5 (taken over from a dropped session; its targeted run of three matrix rows passed on that commit).
- 2026-11-18 (c) product change, kept to timing: `DeviceHost.KillSwitchReapply` (internal/agent) replaces the 10 s re-apply period when shorter; `KillSwitch.SetDirectTimeout` (internal/dataplane/firewall, Linux; a no-op on macOS) replaces DirectTimeout; cmd/thinkpol sets both only with THINKPOL_LAB=1 and THINKPOL_LAB_KILL_SWITCH_REAPPLY of 1 s to under 10 s, the direct timeout three periods as with the defaults; anything else is the defaults (unit test TestLabKillSwitchReapply). The kill-switch lab test sets 2 s/6 s through a systemd drop-in and watches direct4's `expires` restart at the ticks instead of sleeping 45 s; its tick checks bound at 1.5 periods. The firewall in-node expiry test runs a 3 s timeout and watches direct6's `expires`. The dns bind-mount test writes on a tmpfs (0.36 s, was 115 s; 500 iterations kept, so no new false-pass chance; the lock mutation below fails it at update 9). The routetable test waits for Status().Reapplies and the routes instead of sleeping 1 s. Remaining ≥ 1 s sleeps in lab/ and lab-gated tests each say why no watcher sees them (absence windows, perf windows, children that hang until killed). Commits d7e7415f, 72001016 (docs: lab/README.md, lab/censor, agent and firewall doc.go), b8dff653.
- 2026-11-18 out of my scope but in my file: the kill-switch test bounded a refused curl at 3 s by wall time around docker exec; a run at load 14 took 7.9 s around a curl that failed in 0 ms. It now reads curl's own time_total (3ad4cc95).
- 2026-11-18 mutations (each on an uncommitted copy, never pushed): M1 the cmd bound loosened → TestLabKillSwitchReapply fails ("10s, want 0s"); M2 reapplyEvery ignores the host → the agent unit test fails ("the period set to 2s: 10s", after strengthening it: the first version derived the period from the mutated function and passed) and the kill-switch lab test fails "the direct destinations expired 6.0s in, renewed 0 times"; M3 expiry() ignores SetDirectTimeout → TestKillSwitchDirectTimeout fails and the in-node expiry test fails at its 6 s bound showing "present true, expiring in 23.9s"; M4 Reapplies never counted → the routetable test fails at 5 s with the counts and routes; M5 the dns watch reads outside the lock → fails at update 9 on the tmpfs; M6 censord never writes a watermark → TestVerdictLogWatermark fails and the plain-tcp ip-blocklist cell fails at 30 s ("watermark is at packet 0 after 30s, the kernel had queued 2"). `probeBudget.blocked` and realityUp's stop have no failure mode to mutate: a verdict that never comes falls back to the old windows (8 s, 60 s), the cell still scored by its probe (read, not run).
- 2026-11-18 kill-switch lab test, targeted on d7e7415f: 207.9 s (was 276.4 s in an earlier full lab). An instrumented copy shows where it goes, on a host at load ~14: 97.7 s to start the lab (four nodes, one systemd), 13 s to boot, then 110 s of steps (≈25 service state changes and restarts, three crash cycles each waiting out the 6 s expiry, ~200 docker execs).
- 2026-11-18 box 1: `grep -rn 'time.Sleep('` over lab/ and the THINKPOL_LAB-gated tests leaves, at 1 s or more: lab/matrixreset_test.go clearUntilEmpty's 1 s settle (a retransmission is an absence), the supervisor's 2 s cross-space window and 1 s config window, TestSharedListenerThroughput's measurement windows (make lab-perf only), and hour-long sleeps of children that hang until killed (lab/gotest_unix_test.go, lab/reservations_test.go, supervisor_linux_test.go), each commented; lab/censor/modules_prober_test.go's 2 s baseline is a unit test (TP-173). After merging rewrite, TP-243's cache tests (lab/gotestcache_test.go, lab/testcache) add ~2 s sleeps past the file-time clock slack (afterWrites, "the clock slack"): a start must be later than every input's mtime, which no watcher can hurry. Other ≥ 1 s sleeps under internal/ are ordinary unit tests (TP-173).
- 2026-11-18 box 2 left unticked: the budget report is TP-239's, not merged. From this branch's targeted run of three matrix rows (plain-tcp, random-tcp, reality, 18 cells) on 095259d5, the cells' durations have a median of 13.4 s (4.6–32.2 s; reality's 18–26 s, random-tcp's active prober 32 s); the full lab's matrix was not run with -v, so its per-cell times aren't in its log.
- 2026-11-18 box 3 left unticked: the kill-switch lab test runs 208 s targeted (276 s before), 110 s of it the test's own steps after a 98 s lab start and a 13 s systemd boot on a loaded runner; 60 s would need fewer state changes per lab (splitting the test, TP-242's territory), not shorter waits.
- 2026-11-18 full lab on ebc5e83b (rewrite with TP-243 merged in), wall 3328 s with two other full labs running: EXIT 2. The censor matrix ran whole and passed (it rewrote RESULTS.md, not committed), the kill-switch test passed. Failures: TestQueuePipeline/watermarks_what_it_decided (this branch's test: it sent before the censor had bound its queue, and a packet queued to no one gets no id; fixed in 45007026, then 20 of 20 targeted passes); TestCensorForwardsWhatNoModuleDecides (stuck in docker compose up) and TestDisconnectLeavesNothingBehind (a lab-slot wait), both untouched here, passed targeted on 45007026. An earlier full lab on b8dff653 (3742 s, four full labs at once) failed only on lab-slot waits and the package's 60 min cap: no evidence either way.
- 2026-11-18 out of scope: the caught-up wait has one gap: a packet the kernel drops from a full queue still takes an id, so if the last packet queued was dropped, the watermark can't reach it until another packet comes and the read fails at 30 s (QueueDropped already makes the cell an error). The full lab's 60 min cap and 12 lab slots are shared by every concurrent run on the runner: two full labs at once starve each other.
- 2026-11-18 not verified: a full lab on the final head 45007026 (it differs from ebc5e83b, the last full lab, by the queue-binding wait in one test); that test 20 of 20 and the two re-run lab tests passed targeted on it, make lint and make test green on it. The full lab under load is the orchestrator's on rewrite after the merge.
- 2026-11-18 in-progress → review
- 2026-11-19 merged rewrite (TP-244) after the move to review; make lint and make test green on acdb2660
