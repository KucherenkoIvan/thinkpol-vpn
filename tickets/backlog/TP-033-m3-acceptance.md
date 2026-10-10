---
id: TP-033
title: "M3 acceptance"
milestone: M3
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-029, TP-031, TP-032]
refs: [DESIGN#milestones]
owner: ""
branch: ""
---

## Goal
M3's "done when": chains get past a whitelist and survive losing an entry.

## Scope
- `ru-entries → nl-exit` works with whitelist mode on (entries allow-listed, exit not).
- The failover test from TP-031 under the censor.
- Matrix updated.

## Acceptance
- [ ] lab tests green; `lab/RESULTS.md` updated

## Log
- 2026-10-10 created in backlog
