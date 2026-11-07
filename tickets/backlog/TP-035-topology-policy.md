---
id: TP-035
title: "Topology and policy features"
milestone: M4
area: features
stream: administration
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
- [ ] hop groups enforce docs/design/control-plane.md (`topology`) and PRD R6 (members plus an allowed selection policy: `failover`, `lowest-latency`, `spread`)
- [ ] a rule set that references chains or matchers the domain does not allow is rejected with domain errors
- [ ] the controller sets a custom rule for one device, and only that device's part of the map carries it (lab)

## Notes
- **From TP-013 (ingress/egress):** topology policy works with `NodeSettings.AllowIngress`/`AllowEgress` (servers only, both off by default). Turning ingress off removes every link between the server and devices from both sides of the map (Build refuses anything else); devices then reach that server only through relays that allow ingress. Never leave device links on an ingress-off server for the node to filter: a node on an older reader would keep admitting them.
- **TP-139 verdicts (TP-139 owner session, 2026-11-07; docs/design/api-overview.md "Verdicts", docs/design/configuration.md).** Proposal from the orchestrator, not confirmed by the owner: node groups may carry settings; groups are a controller-side abstraction (space defaults, then group, then node) compiled into each node's part of the map, and nodes never see groups, only resolved values (docs/design/configuration.md "Node groups (proposal)").

## Log
- 2026-10-10 created in backlog
- 2026-10-12 docs (TP-013 review): notes from the ingress and egress settings
- 2026-10-15 docs (backlog grooming): acceptance for hop groups and rule-set policy
- 2026-10-15 docs (backlog grooming, review fixes): hop-group acceptance cites DESIGN/PRD R6
- 2026-11-07 TP-139 verdicts noted
- 2026-11-07 docs (MVP triage, PRD R3): acceptance for a per-device custom rule
