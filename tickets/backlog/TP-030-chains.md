---
id: TP-030
title: "Chains"
milestone: M3
area: dataplane
repo: thinkpol-vpn
size: L
depends_on: [TP-015, TP-023]
refs: [R5, N9, DESIGN#data-plane]
owner: ""
branch: ""
---

## Goal
Internet traffic can leave through ordered chains of hops, with several egress nodes in use at once.

## Scope
- Chain definitions in the map, validated by the map builder (N9: first hop allows ingress, last allows egress).
- Multi-relay paths in the path layer (A → B → exit); each relay knows only its next hop.
- Router `chain:<name>` actions with one WireGuard device per egress.

## Acceptance
- [ ] in the lab, one rule goes through `ru → nl` and another straight to `nl`, at the same time
- [ ] a middle relay sees only transport ciphertext (capture)

## Log
- 2026-10-10 created in backlog
