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
- [x] behaviour unchanged: `make lint`, `make test`, `make lab-test` green
- [x] invalid connection transitions are errors with tests
- [x] node events are typed and emitted from runner/engine (not log strings only)

## Notes
- **Owner decision (2026-10-18):** explicit entity modelling without kernel persistence machinery; see PRD "Agent modelling (2026-10-18)".
- TP-041 (telemetry) consumes these events; TP-083's log-scraping replacement builds on them.
- **Where it lives (2026-10-19):** `internal/agent/connection.go` (the state, its transition table `connTransitions` and its methods; a refused move is `errInvalidTransition`, logged at error level, the state unchanged); `internal/agent/events.go` (`Event`, `EventKind`, `Node.Subscribe`); `internal/dataplane/events.go` (`dataplane.Event`, told through `EngineConfig.Events`). The node owns the connection: `awaitSection` moves it while removed, the runner after; a server's worker runs a connection that is always up. Removed/back events come from the map follower, so device, server and the removed start all say them.
- **Engine events are told unlocked:** a subscriber may read `Node.Status`, which calls `Engine.Status`; the engine notes events under its lock and `flushEvents` (deferred first in Apply, SetRules, ReloadRules) tells them after.
- **Status still derives Connected from the running engine:** while the node stops, the connection stays connected but the engine is gone, which the status showed as connecting before this ticket and still does.
- **Not events yet (for TP-083/TP-041):** the route table failing to be put back later (`routetable`'s own reapply, `ErrorReapply`) or the leak guard failing, which only the status shows; a resolver configuration whose `Problem` turns unprotected after it was pointed (another link's domains in systemd-resolved); `SetDirectUpstreams` failing; there is no disconnected or retrying event kind.

## Log
- 2026-10-18 created in backlog (split from TP-083, owner decision)
- 2026-10-19 backlog → in-progress — owner: agent-claude, branch: tp-110-agent-connection-state-with-events
- 2026-10-19 the device's connection is one state (disconnected, connecting, connected, removed, retrying) with transition methods; it replaces the runner's down flag and the node's want; invalid moves are errInvalidTransition, tested over every from/to pair (TestConnectionTransitions) and per event (TestConnectionLifecycle); device and runner tests fail on a refused move in the log
- 2026-10-19 the mode lives in the report alone (Node.Mode reads it); report.set call sites in node.go, dataplane.go and resolver.go down from 11 to 8
- 2026-10-19 typed node events (Node.Subscribe): connected, removed from space, back in space (the map follower, all three paths), DNS unprotected (runner), route table not enforced (engine, EngineConfig.Events, told unlocked); log lines unchanged; tests assert the events heard
- 2026-10-19 docs: DESIGN.md "Engine and agent" describes the connection state and the node's events
- 2026-10-19 merged origin/rewrite: nothing new since the branch was cut
- 2026-10-19 make lint (exit 0) and make test (exit 0) at c8e972c; make lab-test exit 0 at c8e972c (lab suite ok, 35 node packages PASS), 484 s with LAB_P=1 (another lab was running). Not verified here: the route-table and DNS events on a real macOS device (needs a device run)
- 2026-10-19 in-progress → review
