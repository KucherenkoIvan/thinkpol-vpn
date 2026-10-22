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
M3's "done when": chains get past the lab's whitelist mode through an allowlisted entry, and survive losing an entry. The lab models an allowlisted entry; obtaining one in the real world is not promised (DESIGN.md, "Whitelists").

## Scope
- `ru-entries → nl-exit` works with whitelist mode on (entries allow-listed, exit not).
- The failover test from TP-031 under the censor.
- Matrix updated.

## Acceptance
- [ ] lab tests green; `lab/RESULTS.md` updated

## Log
- 2026-10-10 created in backlog
- 2026-10-16 docs: whitelist acceptance through an allowlisted entry the lab models; no real-world promise (owner, 2026-10-16)
