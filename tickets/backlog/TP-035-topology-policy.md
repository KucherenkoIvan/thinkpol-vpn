---
id: TP-035
title: "Topology and policy features"
milestone: M4
area: features
repo: thinkpol-vpn
size: L
depends_on: [TP-034]
refs: [N9, R2, R3, R5, R6]
owner: ""
branch: ""
---

## Goal
Hop groups, chains and rule sets live in the controller with their invariants enforced in the domain.

## Scope
- Aggregates `HopGroup`, `Chain` (invariants from N9), `RuleSet`; events; use-cases; tests with `dddtest`.

## Acceptance
- [ ] invalid chains (first hop without ingress, last hop without egress, a hop group member without them) are rejected with domain errors

## Notes
- **From TP-013 (ingress/egress):** topology policy works with `NodeSettings.AllowIngress`/`AllowEgress` (servers only, both off by default). Turning ingress off removes every link between the server and devices from both sides of the map (Build refuses anything else); devices then reach that server only through relays that allow ingress. Never leave device links on an ingress-off server for the node to filter: a node on an older reader would keep admitting them.

## Log
- 2026-10-10 created in backlog
- 2026-10-12 docs (TP-013 review): notes from the ingress and egress settings
