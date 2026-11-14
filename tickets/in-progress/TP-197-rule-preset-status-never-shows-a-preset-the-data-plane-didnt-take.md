---
id: TP-197
title: "Rule preset: status never shows a preset the data plane didn't take"
milestone: M2
area: agent
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-166]
refs: []
owner: "agent-tp-197"
branch: "tp-197-rule-preset-status-truthful"
---

## Goal
`thinkpol status` and device.json never claim a rule preset the data plane isn't enforcing.

## Scope
- `internal/agent/node.go`, `SetRulePreset` (~lines 193-218): the preset is stored before the data-plane loop takes the request. If the caller's context expires first, or `run()` has already read the rules, device.json and Status show the new preset while the old rules stay enforced until the next restart. Status could say "everything" while traffic is routed by another preset.
- `internal/agent/status_test.go` (~line 1377): the final check can't fail. Make it one that can.
- Unit test: a preset request whose context expires before the data plane takes it leaves status and device.json showing the preset actually enforced (or the data plane applies it on its next start, and status says so).
- Mutation test: a data plane that ignores the requested rules but replies nil fails a test.

## Out of scope
The preset list and the rules each preset contains. This ticket is about what status and device.json report.

## Acceptance
- [ ] a unit test: a preset request whose context expires before the data plane takes it leaves status and device.json showing the preset actually enforced (or the data plane applies it on its next start, and status says so)
- [ ] a mutation where the data plane ignores the requested rules but replies nil fails a test
- [ ] `make lint`, `make test` pass

## Notes
- From TP-166's delta check, 2026-11-07.
- Safety-adjacent: a member could believe all traffic goes through the tunnel while some goes direct.

## Log
- 2026-11-07 created in backlog
- 2026-11-14 backlog → in-progress, owner: agent-tp-197
