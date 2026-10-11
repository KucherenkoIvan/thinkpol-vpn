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
- From TP-006: the composition root builds the transport `Registry` with the socket `Control` from TP-018 (`udp.New(udp.Options{Control})`); the path layer and WireGuard never mark sockets themselves.
- **From TP-010 (`thinkpol up`):**
  - **Supervisor mode.** Build `supervisor.Options{Transports: registry, …}`. Per served space, verify and open its map, then `Space{ID, Config, Inbound: dataplane.AcceptedInbound(section, reg, transport.SpaceID(id), linkMTU).Links}`. `SetListeners` from the **node owner's** section `Node.Listeners` only (dual-stack: both `0.0.0.0:p` and `[::]:p`). Re-run both on every map change.
  - **Worker mode.** `agent.RunDataPlane` takes one Inbound abstraction in device and worker modes. In device mode it opens `Transport.Listen`; in worker mode, `SharedListener.Listen(reg, ListenConfig{Peers: engine.Inbound(l.Transport)})` for each listener on `Session.Listeners`, then `go engine.Serve(l.Transport, listener)`, stopping when `l.Done` closes. Feed `Session.SharedCounters` and `SharedDrops` into the worker's status and telemetry. Workers' veths carry only their dialed links and egress.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-006 review): notes from the path layer
- 2026-10-11 docs (TP-010 review): notes from the shared listener
