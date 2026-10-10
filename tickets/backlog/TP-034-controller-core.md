---
id: TP-034
title: "Controller skeleton and core features"
milestone: M4
area: features
repo: thinkpol-vpn
size: epic
depends_on: [TP-023]
refs: [A1, A2, A6, DESIGN#control-plane-the-controller-on-go-kernel]
owner: ""
branch: ""
---

## Goal
The controller exists as a go-kernel service with spaces, members and nodes.

## Scope (split before starting)
- `thinkpol admin serve` composed on go-kernel (`config`, `app`, `observability`, `sqlite`, `webui`, `grpckit`), listening on overlay addresses only.
- Features `spaces`, `members`, `nodes` per DESIGN.md (domain, application, adapters) with migrations.
- Admin CLI over the same use-cases.
- Decide the fate of the `thinkpol dev` commands from TP-004.

## Notes
- **Shaping rollout (TP-027):** the controller puts shaping, or a new shaping field or value, into a link only when both ends' nodes reported supporting it (DESIGN "Transports own traffic shape"). Nodes register with their agent version and capabilities (transports, and per transport the shaping it implements: `transport.ShapingSupport`); keep the newest report per node and gate shaping in the map builder on it. Encode shaping with the generated `thinkpol.transport.v1.Shaping` (features can't import `transport.Shaping.Marshal`); `netmap.Build` checks it with `internal/shaping`.

## Log
- 2026-10-10 created in backlog
