---
id: TP-075
title: "Agent layer cleanup, part 1"
milestone: M2
area: agent
repo: thinkpol-vpn
size: M
depends_on: [TP-019]
refs: [S1, DESIGN#desktop-client]
owner: "agent-glm"
branch: "tp-075-agent-layer-refactor"
---

## Goal
`internal/agent` has one composition root and one map follower so TP-046 can install the service without copying control flow per OS.

## Scope
- A `Platform` struct built in `cmd/` (adapters today are built in `node.go:239`, `dataplane.go:191-211`, `supervisor_linux.go:92`; `cmd/thinkpol/up.go` calls `agent.Prepare` then `node.Adapters(reload)` and optionally appends the local API adapter).
- One `mapFollower` replacing the three copies (`Node.awaitSection`, `serverSpaces.next`, `runner.next`).

## Out of scope
- Status vocabulary, `waitLog` test synchronisation, transport `Router`/`ListenConfig` split, LIFO cleanup stack and depguard on dataplane imports: TP-083.
- New product features; Windows/Android adapters: TP-047 (after this ticket).

## Acceptance
- [ ] behaviour unchanged for map follow and adapter wiring: `make lint`, `make test`, `make lab-test` green
- [ ] one `mapFollower` with a single `take(envelope)` used from device and server modes

## Notes
- **Split (backlog grooming 2026-10-15):** this ticket is part 1 only. TP-083 takes the rest of the original TP-075 refactor (status vocabulary, `waitLog` removal, cleanup stack, transport split, depguard).
- **Independent review (2026-10-15), file:line evidence (composition root and map follower):** adapters built in `node.go:239`, `dataplane.go:191-211`, `supervisor_linux.go:92` vs `cmd/thinkpol/up.go` (`Prepare`, `Adapters`); map-follow state three times with the same log strings.
- **One `follower.take` (from TP-037 / TP-011):** device mode (`runner.next` in `dataplane.go`) and server mode (`serverSpaces.next` in `node.go`) each run `(*Map).Next` → `openSection` → removed/back-in-space logic. Fold them into one `follower` (current map, section, removed flag) with a single `take(envelope)` both modes call, so the semantics can't drift.
- This is also the architecture correction: the composition root moves from `internal/agent` to `cmd/`, so the data plane's adapters are built and passed in, not built by the core.

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 docs (backlog grooming): milestone M2; split — part 1 (composition root + map follower); TP-083 is part 2
- 2026-10-15 docs (backlog grooming, review fixes): cites and up.go wording; follower semantics from TP-037; Windows dep wording
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-075-agent-layer-refactor
