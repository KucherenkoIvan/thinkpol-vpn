---
id: TP-075
title: "Agent layer cleanup, part 1"
milestone: M2
area: agent
repo: thinkpol-vpn
size: M
depends_on: [TP-019]
refs: [S1, DESIGN#desktop-client]
owner: ""
branch: ""
---

## Goal
`internal/agent` has one composition root and one map follower so TP-046 can install the service without copying control flow per OS.

## Scope
- A `Platform` struct built in `cmd/` (adapters today are built in `node.go:239`, `dataplane.go:191-205`, `supervisor_linux.go:92`; `cmd/thinkpol/up.go:51-68` builds nothing).
- One `mapFollower` replacing the three copies (`Node.awaitSection`, `serverSpaces.next`, `runner.next`).

## Out of scope
- Status vocabulary, `waitLog` test synchronisation, transport `Router`/`ListenConfig` split, LIFO cleanup stack and depguard on dataplane imports: TP-083.
- New product features; Windows/Android adapters (land after TP-083 and TP-047).

## Acceptance
- [ ] behaviour unchanged for map follow and adapter wiring: `make lint`, `make test`, `make lab-test` green
- [ ] one `mapFollower` with a single `take(envelope)` used from device and server modes

## Notes
- **Split (backlog grooming 2026-10-15):** this ticket is part 1 only. TP-083 takes the rest of the original TP-075 refactor (status vocabulary, `waitLog` removal, cleanup stack, transport split, depguard).
- **Independent review (2026-10-15), file:line evidence:** adapters built in `node.go:239`, `dataplane.go:191-205`, `supervisor_linux.go:92` vs `cmd/thinkpol/up.go:51-68`; map-follow state three times with the same log strings.

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 docs (backlog grooming): milestone M2; split — part 1 (composition root + map follower); TP-083 is part 2
