---
id: TP-069
title: "Replays accepted after a supervisor restart"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: M
depends_on: []
refs: [C1, C3, C6, docs/design/transports.md#transports]
owner: ""
branch: ""
---

## Goal
After a supervisor restart, datagram replays within the freshness window do not open links or reach workers in a way that enables active probing.

## Scope
- Address replay acceptance across supervisor restarts. Workers die with the supervisor (`Pdeathsig` at `supervisor_linux.go:859`, re-armed in `sandbox_linux.go:75`); sender and replay state are not persisted (`shared.go:284-290` builds fresh Routers; `RuntimeDir` holds only `forwarding.json`). The second filter `udp/router.go:24-26` assumes a still-running worker Listener; after restart the WireGuard device has no timestamp history either and answers a replayed initiation.
- Pick one approach (implementer chooses; record the decision in DESIGN.md):
  - persist per-credential sender state across restarts;
  - hold listeners closed for one clock window after a start;
  - document the caveat in DESIGN and the threat model.

## Out of scope
- TLS stream replay cache behaviour (separate transport path).
- TP-036 key-epoch recovery.

## Acceptance
- [ ] the chosen mitigation is implemented or documented per Scope, with the decision recorded in DESIGN.md
- [ ] a test: supervisor restart followed by a replay of a captured datagram does not deliver to the worker / does not answer as a fresh initiation (per the chosen approach)

## Notes
- **Independent review (2026-10-15):** replays pass for five minutes after every supervisor restart; a fresh WireGuard device answers them — the active-probing oracle DESIGN.md rules out at lines 99 and 102. References: `supervisor_linux.go:859`, `sandbox_linux.go:75`, `shared.go:284-290`, `udp/router.go:24-26`. No test covered a restart before this ticket.
- **TP-063:** replay and sender state live wherever the pre-auth filter lives after the gatekeeper move; coordinate tests with TP-070 so they are re-homed, not duplicated.

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 docs (backlog grooming): Pdeathsig cite fixed; note on TP-063 filter location
