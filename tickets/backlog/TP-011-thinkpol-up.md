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

## Notes
- Keys and maps (from TP-004's review): `thinkpol up` defines its own state-dir and key-file format in `internal/agent`. It may reuse the on-disk layout of TP-004's dev key files (`<name>.key` with quoted hex `node-id`, `map-key`, `wireguard-key`; `space.pub` with `space-id`, `signing-key`, `recovery-key`; private files 0600, refused when others can read them), but the reader lives outside `internal/devmap`, which depguard keeps to `cmd/thinkpol`'s dev commands. The runtime key types are in `internal/netmap`: `NodePrivateKey`, `WireGuardPrivateKey` (`ParseNodePrivateKey`, `ParseWireGuardPrivateKey`, redacted `String`), and `netmap.Trust`. Load with `netmap.Verify(env, trust)` then `(*Map).Open(mapKey)`; the node's id is `Section.Node.ID`.
- Listeners: a dual-stack server's map has `udp 0.0.0.0:p` and `udp [::]:p`; the udp adapter binds each to its own family (fixed in TP-004), so open both.

## Log
- 2026-10-10 created in backlog
