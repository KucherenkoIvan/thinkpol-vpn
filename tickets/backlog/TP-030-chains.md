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
- **From TP-013 (N9 checks):** the settings are `NodeSettings.AllowIngress`/`AllowEgress`. A chain's first hop must allow ingress, its last egress, every member of a hop group too. Build's cross-section check belongs next to `hiddenFromDevices` in `internal/netmap/envelope.go` (which already keeps every link between devices and ingress-off servers out of the map, and an ingress-off server's addresses out of devices' sections); devmap's next to the ingress check in `checker.paths` (`internal/devmap/spec.go`).

- **From TP-022's review:** chain (egress) names reach the local API's status and the tray as WireGuard device names: restrict them to `[a-z0-9-]` (and a sane length) when the map is parsed, so nothing a map says can act on a terminal. The local API sanitizes them server- and client-side meanwhile.
- Split before starting (backlog grooming 2026-10-15).
- **From TP-014 (egress):** an exit is a server in server mode whose section allows egress; nothing more on the exit side. Middle hops need no egress: a worker's dials to the endpoints its section lists leave the root namespace by the uplink, in the transport's protocol (`Transport.Network()`), whatever the egress, but endpoints on private networks are refused unless the node's `EgressAllowed` (`-egress-allowed`) names them. devmap checks a chain's exit (egress, a path to it) at the chain's position. An exit without IPv6 answers IPv6 with "no route", so the device falls back to IPv4 by itself.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): chains in use at once end at different exits; acceptance uses `de` for the second exit; destination routing
- 2026-10-10 docs (TP-006 review): notes from the path layer
- 2026-10-12 docs (TP-013 review): notes from the ingress and egress settings
- 2026-10-12 docs (TP-014 review): notes from egress on Linux
- 2026-10-15 docs (backlog grooming): split note
