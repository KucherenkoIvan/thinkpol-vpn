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
- Chain definitions in the map, validated by the map builder (N9: first hop allows ingress, last allows egress). The builder also rejects a rule set that uses two chains ending at the same exit: WireGuard holds one session per exit and the path layer uses one path per exit at a time (DESIGN "Routing rules and DNS").
- Multi-relay chains by destination routing (A → B → exit): the device knows its candidate first hops, each relay only its next hop toward the exit (`netmap.Section.Routes`).
- Router `chain:<name>` actions with one WireGuard device per egress.

## Acceptance
- [ ] in the lab, one rule goes through `ru → nl` and another straight to `de`, at the same time
- [ ] the map builder rejects rules that use two chains ending at the same exit
- [ ] a middle relay sees only transport ciphertext (capture)

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): chains in use at once end at different exits; acceptance uses `de` for the second exit; destination routing
