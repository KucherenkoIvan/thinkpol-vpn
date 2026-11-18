---
id: TP-248
title: "TestKillSwitchUnderSystemd split into parts that each take ≤ 60 s of lab"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-241]
refs: []
owner: ""
branch: ""
---

## Goal
The owner wants a full lab to take at most 15 minutes on the remote runner (2026-11-16); after the lab-speed tickets the default stream still took ~36 minutes (TP-239's measurement, 2026-11-19). After TP-241 the test takes ~208 s (≈98 s lab start under load, ≈13 s systemd boot, ≈110 s for ~25 state changes); TP-241's box "kill-switch test ≤ 60 s" moved here.

## Scope
- Split by the behaviour each part proves (independent parts in parallel labs, or one lab with parallel subtests where state allows), keeping every assertion.

## Out of scope
The 3 s refusal limit's flake: TP-246.

## Acceptance
- [ ] Each part ≤ 60 s in use. Evidence: the budget report.
- [ ] Every assertion of the original kept (list in Notes).

## Notes

## Log
- 2026-11-19 created in backlog (lab-speed follow-ups)
