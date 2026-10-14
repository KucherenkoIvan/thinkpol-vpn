---
id: TP-075
title: "Agent-layer refactor before more OS adapters"
milestone: M1
area: agent
repo: thinkpol-vpn
size: L
depends_on: [TP-019]
refs: [S1, DESIGN#desktop-client]
owner: ""
branch: ""
---

## Goal
`internal/agent` is a single coherent composition root so further OS adapters do not multiply copy-pasted control flow.

## Scope
- A `Platform` struct built in `cmd/` (adapters today are built in `node.go:239`, `dataplane.go:194-209`, `supervisor_linux.go:92`; `cmd/thinkpol/up.go:51-68` builds nothing).
- One `mapFollower` replacing the three copies (`Node.awaitSection`, `serverSpaces.next`, `runner.next`).
- One LIFO cleanup stack owned by the engine (teardown order today depends on where `defer` sits; three hand-written unwind paths in `runner.start`).
- Split `transport.Router` and `ListenConfig`.
- One typed status vocabulary (today mixes snake_case codes, lowercase step words and English sentences; `EgressInfo.Err` is raw `err.Error()`).
- Status-based test synchronisation instead of `waitLog` on log text (~twenty agent tests).
- depguard rule: `internal/dataplane/*.go` (core package files) may not import `routetable`, `dns` or `tun`.

## Out of scope
- New product features; Windows/Android adapters (land after this).

## Acceptance
- [ ] behaviour unchanged: `make lint`, `make test`, `make lab-test` green
- [ ] depguard rule in `.golangci.yml` denying `routetable`, `dns`, `tun` imports from `internal/dataplane/*.go`
- [ ] no `waitLog` on log text left in `internal/agent` tests

## Notes
- **Independent review (2026-10-15), file:line evidence:** adapters built in `node.go:239`, `dataplane.go:194-209`, `supervisor_linux.go:92` vs `cmd/thinkpol/up.go:51-68`; map-follow state three times with the same log strings; three DI styles on `DataPlane` (ten private hook fields, package-level swappable vars, `tweak func`); Linux-shaped ports (`netcfg.Rule` with `Oif`, `Mark`, `SuppressDefaultRoutes`; `routetable.Config` without build tags); `dataplane/routetable.go:17-21` declared in terms of `routetable.Want`; `engine.go:103` imports `dns`; status vocabulary not fixed; ~twenty tests use `waitLog("map applied")` though `Status().MapVersion` exposes the fact.

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
