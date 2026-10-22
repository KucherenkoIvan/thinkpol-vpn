---
id: TP-134
title: "`thinkpol rollback`: undo what a dead agent left, as a product command"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: []
refs: [docs/design/security.md#kill-switch]
owner: ""
branch: ""
---

## Goal
A user (or the device-test harness) whose agent crashed can put the host back with one root command: no routes, guard, pf reference or resolver configuration of thinkpol's left.

## Scope
- `sudo thinkpol rollback`: under the host lock (refused while an agent runs), run the agent's start-time cleanup (`agent.Platform.ClearHost`, the same `up -connect=false` runs), report what it undid and what is left. With the persisted connect state (TP-046) and the kill switch (TP-048), say what rollback means for a device that should stay fail-closed after a crash: rollback is the user choosing to go back to no tunnel.
- The same command serves the harness's last-resort restore (TP-082) and the docs' crash recovery, replacing the by-hand route deletions in the runbooks.
- TP-132 (uninstall after a server crash) may share it: say which owns the supervisor's cleanup.

## Acceptance
- [ ] lab: SIGKILL a connected device's agent, `thinkpol rollback` leaves the host as before `up` (routes, nft table, resolver configuration)
- [ ] refused while an agent runs (a test)
- [ ] `make lint`, `make test`, `make lab-test` pass
- [ ] macOS: device checklist step (pf anchor, reference and token record gone, routes and DNS back)

## Notes
- Owner's answer to the device-harness questions (2026-10-23, TP-082 question 4).

## Log
- 2026-10-23 created in backlog (TP-082 design answers)
