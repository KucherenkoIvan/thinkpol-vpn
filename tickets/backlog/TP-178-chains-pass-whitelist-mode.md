---
id: TP-178
title: "Chains pass the lab's whitelist mode through an allowlisted entry"
milestone: later
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-033, TP-177]
split_from: TP-033
refs: [docs/design/milestones.md#milestones]
owner: ""
branch: ""
---

## Goal
Chains get past the lab's whitelist mode through an allowlisted entry. The lab models an allowlisted entry; obtaining one in the real world is not promised (docs/design/security.md, "Whitelists").

## Scope
- `ru-entries → nl-exit` works with whitelist mode on (entries allow-listed, exit not).
- The failover test from TP-031 under whitelist mode.
- Matrix updated.

## Acceptance
- [ ] lab tests green; `lab/RESULTS.md` updated

## Notes
- Split from TP-033, 2026-11-07, owner's MVP cut (whitelist mode deferred). Depends on TP-177, which builds whitelist mode.

## Log
- 2026-11-07 created in backlog (split from TP-033)
