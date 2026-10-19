---
id: TP-110
title: "Agent: the connection as a state type with events"
milestone: M2
area: agent
repo: thinkpol-vpn
size: M
depends_on: [TP-075]
split_from: TP-083
refs: [S1, DESIGN#desktop-client]
owner: "agent-claude"
branch: "tp-110-agent-connection-state-with-events"
---

## Goal
The device's connection lifecycle is one explicit state with transition methods and typed node events, replacing flag combinations and duplicate mode fields.

## Scope
- Explicit connection state (disconnected, connecting, connected, removed, retrying) with transition methods, replacing the flag combinations in the runner's connect/retry/next (`internal/agent/dataplane.go` ~447-640).
- One source of truth for mode (`n.mode` vs `n.report.mode` today).
- Typed node events (removed from space, back in space, connected, DNS unprotected, route table not enforced) emitted by the runner and engine; fewer `report.set` call sites.
- Invariants live in the transition methods; invalid transitions return errors and are tested.

## Out of scope
- Repositories, transaction manager or other persistence machinery for one state file.
- Engine struct split along field blocks: TP-083.
- Data-plane port types in the core: TP-109.

## Acceptance
- [ ] behaviour unchanged: `make lint`, `make test`, `make lab-test` green
- [ ] invalid connection transitions are errors with tests
- [ ] node events are typed and emitted from runner/engine (not log strings only)

## Notes
- **Owner decision (2026-10-18):** explicit entity modelling without kernel persistence machinery; see PRD "Agent modelling (2026-10-18)".
- TP-041 (telemetry) consumes these events; TP-083's log-scraping replacement builds on them.

## Log
- 2026-10-18 created in backlog (split from TP-083, owner decision)
- 2026-10-19 backlog → in-progress — owner: agent-claude, branch: tp-110-agent-connection-state-with-events
