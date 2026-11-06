---
id: TP-185
title: "Access grants: chains per member, device reachability"
milestone: M4
area: features
repo: thinkpol-vpn
size: M
depends_on: [TP-035]
refs: [A3]
owner: ""
branch: ""
---

## Goal
An admin decides which chains a member may use, and whether a device is reachable by the whole space or only by its owner (PRD A3).

## Scope
- Grants in the controller: the chains a member may use; a device's reachability, the whole space or its owner only.
- The projector puts only granted chains in a member's devices' parts of the map, and drops links and routes to a device from the parts of devices that may not reach it.
- A default for reachability.

## Out of scope
- Chains and rule sets themselves: TP-035.
- The panel's pages for grants: TP-042.

## Acceptance
- [ ] domain tests: a grant naming a chain the space doesn't have is rejected; revoking a chain removes it from the member's devices' next map
- [ ] lab: a member's device uses a granted chain and can't use one it wasn't granted
- [ ] lab: an owner-only device is reachable from its owner's other device and not from another member's
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Source: MVP triage 2026-11-07 against PRD A3.
- Default reachability: to be decided by the owner. An earlier recommendation suggests owner-only; it is not decided.

## Log
- 2026-11-07 created in backlog (MVP triage against PRD A3)
