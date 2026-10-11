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

## Notes
- From TP-006: multi-relay chains work by `Routes` already (path layer). Relays check sources loosely (a source they have no route to and aren't adjacent to is dropped), because maps needn't route both ways alike; make the builder's routes symmetric (each relay routes back to every source it carries through the hop that source's traffic arrives from) so a strict reverse-path check can come back. First and next hops must be adjacent, or the engine drops them. The builder computes a space-wide overlay MTU from the links' budgets (`path.MessageBudget`), so every device uses one TUN MTU.

- **From TP-022's review:** chain (egress) names reach the local API's status and the tray as WireGuard device names: restrict them to `[a-z0-9-]` (and a sane length) when the map is parsed, so nothing a map says can act on a terminal. The local API sanitizes them server- and client-side meanwhile.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): chains in use at once end at different exits; acceptance uses `de` for the second exit; destination routing
- 2026-10-10 docs (TP-006 review): notes from the path layer
