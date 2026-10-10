---
id: TP-040
title: "Hosting grants and shared nodes"
milestone: M4
area: features/hosting
repo: thinkpol-vpn
size: epic
depends_on: [TP-036, TP-010]
refs: [A10, N5, N6, N7, DESIGN#server-agent-one-worker-per-space]
owner: ""
branch: ""
---

## Goal
A node owner shares a server node with another space, fully isolated, capped and revocable.

## Scope (split before starting)
- `HostingGrant` aggregate; offer and accept tokens passed between two controllers.
- The node owner's map lists guest spaces (public key, cap, ingress/egress granted).
- Supervisor starts guest workers and accepts guest envelopes for those workers only.
- Bandwidth caps and fair share between spaces.
- The guest controller's view: shared node as an endpoint plus the grant, read-only.
- Revocation on both sides.

## Log
- 2026-10-10 created in backlog
