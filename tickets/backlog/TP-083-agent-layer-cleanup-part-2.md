---
id: TP-083
title: "Agent layer cleanup, part 2"
milestone: M2
area: agent
repo: thinkpol-vpn
size: L
depends_on: [TP-075, TP-109, TP-110]
split_from: TP-075
refs: [S1, DESIGN#desktop-client]
owner: ""
branch: ""
---

## Goal
Finish the agent-layer refactor after TP-075, TP-109 and TP-110: teardown order, transport wiring split, typed status and tests that don't scrape logs.

## Scope
- One LIFO cleanup stack owned by the engine (teardown order today depends on where `defer` sits; three hand-written unwind paths in `runner.start`).
- Split `transport.Router` and `ListenConfig`.
- One typed status vocabulary (today mixes snake_case codes, lowercase step words and English sentences; `EgressInfo.Err` is raw `err.Error()`).
- Status-based test synchronisation instead of `waitLog` on log text (~twenty agent tests), driven by TP-110's node events.
- Split `Engine` along the invariants each block protects (`internal/dataplane/engine.go` ~121-194): one owner for "a peer key lives on one device", one for "direct routes shrink before the router table changes and grow after".
- One table each for counters (`internal/agent/localapi/convert.go` ~61-81 with `render.go` ~176), refusals (`errors.go` ~18-32, `client.go` ~191-201) and display names (`enumName`).
- Move `cmd/thinkpol/dev_lists_build.go` logic (~41-83) out of `cmd/`.
- Deduplicate the six command files' shared socket flag and dial prologue.
- The remaining private test hooks on `DataPlane` and `Node` (path, retryAfter, blobOptions, onEngine, dnsPort, `Node.tweak`): where they stay, say so in one place; where a typed status (this ticket) can replace them, drop them.

## Out of scope
- Data-plane port types and depguard on core imports: TP-109.
- Connection state type and node events: TP-110.
- New product features; Windows/Android adapters (TP-047).

## Acceptance
- [ ] behaviour unchanged: `make lint`, `make test`, `make lab-test` green
- [ ] the depguard rule from TP-109 stays green
- [ ] no `waitLog` on log text left in `internal/agent` tests

## Notes
- **Split (backlog grooming 2026-10-15):** split from TP-075; part 1 (composition root and map follower) must land first for TP-046.
- **Independent review (2026-10-15), file:line evidence (part 2 slice):** three DI styles on `DataPlane` (ten private hook fields, package-level swappable vars, `tweak func`); Linux-shaped ports (`netcfg.Rule` with `Oif`, `Mark`, `SuppressDefaultRoutes`; `routetable.Config` without build tags); `dataplane/routetable.go:17-21` declared in terms of `routetable.Want`; `engine.go:103` imports `dns`, which justified the depguard rule (now TP-109); status vocabulary not fixed; ~twenty tests use `waitLog("map applied")` though `Status().MapVersion` exposes the fact.

- **Host in the worker (TP-075 review round 3):** `agent.Host` carries device-only adapters (TUN configurator, route table, leak guard, OS resolver configuration) into the sandboxed worker too; only `DataPlane.Forward` and `DataPlane.RouteTable` keep the worker off them. A narrower worker port, or a check that refuses them, belongs with the port split here.

## Log
- 2026-10-15 created in backlog (split from TP-075, backlog grooming)
- 2026-10-15 docs (backlog grooming, review fixes): recovered part-2 evidence note from original TP-075
- 2026-10-18 split: port ownership → TP-109, connection state and events → TP-110; Engine split and local API tables added (owner)
- 2026-10-19 docs (TP-075 review round 2): the remaining private test hooks on DataPlane and Node (path, retryAfter, onEngine, dnsPort, tweak) are this ticket's scope
- 2026-10-19 docs (TP-075 review round 3): blobOptions joins the private test hooks; note that Host reaches the worker kept off its device-only adapters only by the Forward and RouteTable flags
