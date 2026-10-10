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

## Log
- 2026-10-10 created in backlog
