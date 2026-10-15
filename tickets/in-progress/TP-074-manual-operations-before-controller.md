---
id: TP-074
title: "Manual operations before the controller"
milestone: M2
area: ops
repo: thinkpol-vpn
size: M
depends_on: []
refs: [A4, S2]
owner: "glm-tp074"
branch: "tp-074-manual-ops"
---

## Goal
The pre-M4 operating model is documented and tooled: map distribution, restarts, updates and clock health without a controller.

## Scope
- A runbook for the period before M4: copying `map.bin` to nodes, restarting after VPS reboots, updating binaries over SSH.
- A map-rotation helper command.
- A clock-skew health code (nodes must agree within 5 minutes).
- chrony/NTP setup (also referenced from TP-038).

## Out of scope
- Anything the controller (M4) automates.

## Acceptance
- [ ] runbook committed and covers map copy, reboot recovery and binary updates over SSH
- [ ] map-rotation helper command exists and is documented in the runbook
- [ ] health reports clock skew beyond 5 minutes
- [ ] chrony/NTP setup documented for nodes

## Notes
- **Independent review (2026-10-15):** until M4 there is no ticket for hand-operated map distribution, reboot recovery, or clock checks.

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 backlog → in-progress — owner: glm-tp074
