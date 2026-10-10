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

## Log
- 2026-10-10 created in backlog
