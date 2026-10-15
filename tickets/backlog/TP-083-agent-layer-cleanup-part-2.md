---
id: TP-083
title: "Agent layer cleanup, part 2"
milestone: M2
area: agent
repo: thinkpol-vpn
size: L
depends_on: [TP-075]
split_from: TP-075
refs: [S1, DESIGN#desktop-client]
owner: ""
branch: ""
---

## Goal
Finish the agent-layer refactor after TP-075: teardown order, transport wiring split, typed status and tests that don't scrape logs.

## Scope
- One LIFO cleanup stack owned by the engine (teardown order today depends on where `defer` sits; three hand-written unwind paths in `runner.start`).
- Split `transport.Router` and `ListenConfig`.
- One typed status vocabulary (today mixes snake_case codes, lowercase step words and English sentences; `EgressInfo.Err` is raw `err.Error()`).
- Status-based test synchronisation instead of `waitLog` on log text (~twenty agent tests).
- depguard rule: `internal/dataplane/*.go` (core package files) may not import `routetable`, `dns` or `tun`.

## Out of scope
- New product features; Windows/Android adapters (TP-047).

## Acceptance
- [ ] behaviour unchanged: `make lint`, `make test`, `make lab-test` green
- [ ] depguard rule in `.golangci.yml` denying `routetable`, `dns`, `tun` imports from `internal/dataplane/*.go`
- [ ] no `waitLog` on log text left in `internal/agent` tests

## Notes
- **Split (backlog grooming 2026-10-15):** split from TP-075; part 1 (composition root and map follower) must land first for TP-046.
- **Independent review (2026-10-15), file:line evidence (part 2 slice):** three DI styles on `DataPlane` (ten private hook fields, package-level swappable vars, `tweak func`); Linux-shaped ports (`netcfg.Rule` with `Oif`, `Mark`, `SuppressDefaultRoutes`; `routetable.Config` without build tags); `dataplane/routetable.go:17-21` declared in terms of `routetable.Want`; `engine.go:103` imports `dns`, which justifies the depguard rule; status vocabulary not fixed; ~twenty tests use `waitLog("map applied")` though `Status().MapVersion` exposes the fact.

## Log
- 2026-10-15 created in backlog (split from TP-075, backlog grooming)
- 2026-10-15 docs (backlog grooming, review fixes): recovered part-2 evidence note from original TP-075
