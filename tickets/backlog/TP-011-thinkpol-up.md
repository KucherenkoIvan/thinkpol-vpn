---
id: TP-011
title: "`thinkpol up`: composing a node"
milestone: M0
area: cmd
repo: thinkpol-vpn
size: M
depends_on: [TP-004, TP-008, TP-010]
refs: [S1, DESIGN#desktop-client]
owner: ""
branch: ""
---

## Goal
One command starts a node from its keys and map: device mode on a device, supervisor mode on a server.

## Scope
- Configuration with go-kernel `config` (env + flags: state dir, map path, mode).
- Composition with go-kernel `app.Run`: TUN, WireGuard, path layer, transports, supervisor or worker; logging with `observability`.
- Map loaded and verified at start; refuse to start on an invalid map.
- State dir layout (`/var/lib/thinkpol`): only the node's own keys and its map (S1).
- Graceful shutdown with netcfg cleanup.

## Acceptance
- [ ] lab nodes start with `thinkpol up`
- [ ] SIGTERM leaves no interfaces, routes or namespaces behind
- [ ] the state dir contains nothing but keys and the map

## Log
- 2026-10-10 created in backlog
