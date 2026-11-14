---
id: TP-172
title: "Split `agent/dataplane.go` and `dataplane/engine.go` by responsibility"
milestone: later
area: agent
stream: core
repo: thinkpol-vpn
size: M
depends_on: []
refs: [docs/design/overlay.md#node-agent]
owner: ""
branch: ""
---

## Goal
The two files M2's features land on are split by responsibility before those features arrive, so each change touches a small file that does one thing. No behaviour changes.

## Scope
- `internal/agent/dataplane.go`: 899 lines, 8 named types (`DataPlane`, `tuning`, `connectRequest`, `rulesRequest`, `runner`, `startPorts`, `listenerSet`, `served`). Split into files by responsibility (e.g. the run loop, connect and rules requests, start-up ports, listeners).
- `internal/dataplane/engine.go`: 603 lines, 5 types (`Step`, `EngineConfig`, `Engine`, `Status`, `PeerStatus`). Split the status types and the configuration out of the engine's loop.
- Moves only: no renamed exported identifiers, no logic changes. The package docs updated if they name a file.

## Out of scope
- Any behaviour change or refactoring of the logic itself.

## Acceptance
- [ ] no file in either package over about 400 lines, each named for what it holds
- [ ] `git diff --stat` and a review show moves only (same declarations, same bodies)
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Source: a code-quality pass on 2026-11-07, recorded at the TP-139 owner session, 2026-11-07.
- Counts checked at the time of filing (2026-11-07, `rewrite` at e6aeb54 merged): the brief said "9+ types" for `dataplane.go`; it has 8 named types and one anonymous struct field.
- Do this before TP-166, TP-111 and TP-048 touch these files, or merge it between them.

## Log
- 2026-11-07 created in backlog
- 2026-11-07 milestone → later (owner's MVP cut: refactor)
