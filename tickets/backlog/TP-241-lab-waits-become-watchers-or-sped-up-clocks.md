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
owner: ""
branch: ""
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
- [ ] grep shows no `time.Sleep` ≥ 1 s in lab/ or in-node tests outside the long stream, each remaining one commented with why no watcher can see it.
- [ ] Matrix cells' median in-use ≤ 10 s. Evidence: the budget report.
- [ ] Kill-switch lab test in use ≤ 60 s.

## Notes
- Saving: ~10–12 min of summed lab in-use time: ~30 blocked cells × 10–16 s, 2 × 60 s reality, ~70 s kill switch, ~100 s dns, prober ~1–2 min. On the critical path after TP-240, ~1–2 min per matrix row.
- Overlaps TP-200 (waits on `status -json` instead of log greps, one node-start helper): same waits (`waitOutput` patterns) and files. Land TP-200 first, or do group (b) inside it.
- Related: TP-173 (fixed sleeps across all tests, milestone later).

## Log
- 2026-11-16 created in backlog (owner: lab fixes, top priority; from the lab-speed audit)
