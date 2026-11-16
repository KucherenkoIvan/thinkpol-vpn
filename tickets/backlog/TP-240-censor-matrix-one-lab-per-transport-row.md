---
id: TP-240
title: "The censor matrix runs one lab per transport row"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: L
depends_on: [TP-223]
refs: []
owner: ""
branch: ""
---

## Goal
The censor matrix costs 9 labs, not 90. The owner wants a full lab to take at most 15 minutes on the remote runner. Measured 2026-11-16: a clean full lab takes 2823 s, and the remote runner's Docker starts only ~18–20 containers a minute, while a run starts 836 containers: the censor matrix 574 of them in 90 labs, each cell in use only 5–30 s.

## Scope
- `TestCensorMatrix` (lab/results_test.go:44) starts one Upstream lab per transport row and runs `off` and then each censored case in it, in sequence.
- Between cells: stop the transport's processes, stop censord and remove its nft and queue tables, flush the router's conntrack, and start a fresh verdict log.
- Then check the reset held: no `censor*` table, no queue rule, no leftover processes or flows.

## Out of scope
- Moving the rhythm cell to the long-wait stream: TP-239.

## Acceptance
- [ ] `docker events` for a full lab shows ≤ 9 matrix labs. Evidence: the run's container-start count by owner, in the ticket Log.
- [ ] RESULTS.md is identical in verdicts to one made with per-cell labs on the same commit. Evidence: a diff of two runs' RESULTS.md.
- [ ] A mutant that skips the reset step fails a cell. Evidence: the mutation run's output.

## Notes
- Saving: ~510 container starts ≈ 28 min of Docker time.
- Do it before or with TP-239 (the long-wait stream moves the rhythm cell out).

## Log
- 2026-11-16 created in backlog (owner: lab fixes, top priority; from the lab-speed audit)
