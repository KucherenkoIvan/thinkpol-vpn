---
id: TP-109
title: "Data-plane ports owned by the core"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: L
depends_on: [TP-075]
split_from: TP-083
refs: [S1, DESIGN#desktop-client]
owner: "agent-claude"
branch: "tp-109-data-plane-ports-owned-by-the-core"
---

## Goal
The data-plane core owns its port types; netcfg, routetable and dns adapt to them, matching transport, Inbound, blobs and routetable.Guard.

## Scope
- Move port types into `internal/dataplane`: an interface config, a route-table want/status and a resolver config holding only what the engine means.
- netcfg, routetable and dns adapt to those types; adapter-only fields (`Rule.Oif`, `Rule.Mark`, `Want.Upstreams`, the per-OS `netcfg.Survey` union) stay in the adapters.
- Stop naming adapter packages' types from the core (`engine.go` ~62, ~105, ~353; `routetable.go` ~18-19).
- Pattern: `transport.Dialer`/`Listener`/`Link`, `agent.Inbound`, `blobs.Store`, `routetable.Guard`.

## Out of scope
- Engine field split, connection state and node events: TP-110.
- Agent-layer status vocabulary, `waitLog` replacement and local API tables: TP-083.

## Acceptance
- [ ] behaviour unchanged: `make lint`, `make test`, `make lab-test` green
- [ ] depguard rule in `.golangci.yml`: `internal/dataplane/*.go` may not import `routetable`, `dns` or `tun`

## Notes
- **Split (2026-10-18):** port ownership carved out of TP-083; lands before TP-083's remaining work.
- **Evidence on `rewrite`:** `EngineConfig.Interface` is `netcfg.Configurator` (`internal/dataplane/engine.go:62`); `DNS` is `interface{ Update(dns.Config) }` (`engine.go:105`); `RouteTable.Enforce` takes `routetable.Want` (`internal/dataplane/routetable.go:18-19`).

## Log
- 2026-10-18 created in backlog (split from TP-083, owner decision)
- 2026-10-19 backlog → in-progress — owner: agent-claude, branch: tp-109-data-plane-ports-owned-by-the-core
