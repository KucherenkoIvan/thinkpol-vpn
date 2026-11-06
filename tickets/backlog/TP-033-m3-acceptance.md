---
id: TP-033
title: "M3 acceptance"
milestone: M3
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-029, TP-031, TP-032]
refs: [docs/design/milestones.md#milestones]
owner: ""
branch: ""
---

## Goal
M3's "done when": chains work under the lab censor and survive losing their active entry.

## Scope
- `ru-entries → nl-exit` works under the lab censor.
- The failover test from TP-031 under the censor: killing the active entry keeps an open connection alive.
- Matrix updated.

## Out of scope
- The pass through the lab's whitelist mode via an allowlisted entry: TP-178 (after the MVP).

## Acceptance
- [ ] lab tests green; `lab/RESULTS.md` updated

## Notes
- Split 2026-11-07 (owner's MVP cut): the whitelist pass through an allowlisted entry moved to TP-178 (whitelist mode deferred); docs/design/milestones.md's M3 row updated.

## Log
- 2026-10-10 created in backlog
- 2026-10-16 docs: whitelist acceptance through an allowlisted entry the lab models; no real-world promise (owner, 2026-10-16)
- 2026-11-07 split (owner's MVP cut): whitelist pass → TP-178
