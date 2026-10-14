---
id: TP-077
title: "Split DESIGN.md into model and package docs"
milestone: M2
area: docs
repo: thinkpol-vpn
size: L
depends_on: [TP-023]
refs: [DESIGN]
owner: ""
branch: ""
---

## Goal
DESIGN.md keeps the model, invariants and decisions. Mechanism moves into package docs (`doc.go`). A residual-risks table collects every accepted residual so leak promises in PRD R4 and D6 can be stated honestly against it.

## Scope
- Shrink DESIGN.md to the model, invariants and architecture decisions.
- Move mechanism detail into per-package `doc.go` (or equivalent package docs), each reachable from the model doc.
- Add a residual-risks table covering at least: the CNAME leak, the macOS TunnelVision window, the IPv4 window when the TUN drops, udp's exposure, the replay-after-restart caveat, and any others found while splitting.
- Update PRD R4 and D6 to qualify leak promises against that table.

## Out of scope
- Changing the technical behaviour described; this is documentation structure only.

## Acceptance
- [ ] DESIGN.md is under a third of its current size
- [ ] every moved mechanism is reachable from a package doc
- [ ] the residual-risks table exists, and PRD R4 and D6 reference it

## Notes
- The author wants extensive documentation for this; it is deferred until after M1.

## Log
- 2026-10-15 created in backlog
