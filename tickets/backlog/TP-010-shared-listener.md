---
id: TP-010
title: "Shared listener and connection handoff"
milestone: M0
area: agent
repo: thinkpol-vpn
size: M
depends_on: [TP-005, TP-009]
refs: [N6, DESIGN#server-agent-one-worker-per-space]
owner: ""
branch: ""
---

## Goal
The node's public address belongs to the supervisor, which authenticates every connection and hands it to the right space's worker.

## Scope
- Supervisor listens on the configured public ports of each transport.
- Runs the transport's authentication, maps the credential to a space, hands the connection over: stream connections by passing the file descriptor (`SCM_RIGHTS`), datagram flows by forwarding per connection id over the worker socket.
- Unauthenticated connections go to the camouflage handler and never reach a worker.
- Per-space credential tables loaded from each space's map.

## Acceptance
- [ ] in the lab, two spaces on one server (hand-made maps): each worker receives only its own links
- [ ] bad credentials never reach any worker

## Log
- 2026-10-10 created in backlog
