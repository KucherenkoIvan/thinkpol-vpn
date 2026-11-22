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
owner: ""
branch: ""
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
- [ ] Critical path before/after from the timeline (which tests end last, when they started), in Notes.
- [ ] Warm full lab default stream before/after, in Notes (target: ≥ 2 min faster).
- [ ] No new flakes: the full lab green twice.

## Notes
- Baseline: TP-261's final head 3b356c7c, full lab twice: 897 s (default 14m57s) and 713 s (default 11m53s).

## Log
- 2026-11-19 created in backlog (owner: do 1-2)
