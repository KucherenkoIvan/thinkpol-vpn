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
- [x] a unit test: a preset request whose context expires before the data plane takes it leaves status and device.json showing the preset actually enforced (or the data plane applies it on its next start, and status says so)
- [x] a mutation where the data plane ignores the requested rules but replies nil fails a test
- [ ] `make lint`, `make test` pass (lint green; test green but for the rewrite flake TestResolvConfAFileRenamedInIsTakenAtOnce, see the Log)

## Notes
- From TP-166's delta check, 2026-11-07.
- Safety-adjacent: a member could believe all traffic goes through the tunnel while some goes direct.

## Log
- 2026-11-07 created in backlog
- 2026-11-14 backlog → in-progress, owner: agent-tp-197
- 2026-11-14 design: status and device.json change only once the data plane has taken the preset, not a "pending" state (one state fewer: there is never a stored-but-unapplied preset to show). The goroutine that runs the device takes the request: it stores device.json (a failed store changes nothing), hands the rules to the engine (Engine.SetRules) and keeps them for every later start, then sets the status. Cases: a ctx that ends before the request is taken changes nothing (no file write, no status change); one that ends after finds it taken; run() having read the rules already is fine, as the request is taken by that run's loop afterwards; a restart between the store and the engine call reads the stored preset, so the next start enforces it; two racing requests are taken one after the other by the one goroutine (presetMu keeps one in flight), the last one taken wins in the file, the engine and status alike; a node waiting for a section (awaitSection) stores and shows it, and the data plane then starts with it; a stopped node only stores it for its next start. An engine whose route table fails after SetRules still follows the new rules (its ownRules) and Status reports route_table_not_enforced.
- 2026-11-14 the ticket's "status_test.go ~line 1377" no longer exists (the file has 1099 lines; on 2026-11-07 it had 744). The vacuous final check is TestARulePresetSetBeforeTheNodeRunsIsTaken's `st.RulePreset != "all-but-domestic"`: SetRulePreset set the status itself before the data plane took anything. Shown: on rewrite 8d19be5 with the runner's rulesRequests case reduced to `req.done <- nil` (the data plane ignores the rules), that test still passed. It now checks the device file, Status.RulePreset and the data plane's own Status.DataPlane.Rules.Preset (wantPreset), and checks that nothing shows the preset while the request waits.
- 2026-11-14 tests: TestARulePresetRequestTheNodeNeverTookChangesNothing (ctx expires before the data plane takes it: status, device.json, the started data plane and a restart all keep "space"), TestARulePresetSetWhileDisconnectedIsTakenByTheConnect, TestARemovedDeviceTakesARulePreset; wantPreset added to TestRulePresetIsStoredByTheService and TestARulePresetSetBeforeTheNodeRunsIsTaken.
- 2026-11-14 mutations, each failing at least one test, each restored: M1 store and show the preset before the request is taken (the old order) fails NeverTookChangesNothing and SetBeforeTheNodeRuns; M2 the data plane stores and shows the preset but never calls Engine.SetRules and replies nil fails RulePresetIsStoredByTheService and SetBeforeTheNodeRuns ("the data plane enforces space"); M3 the data plane ignores the request and replies nil fails the same two; M4 the runner keeps its old rules for the next start fails SetWhileDisconnectedIsTakenByTheConnect; M5 the runner never updates status fails RulePresetIsStoredByTheService and SetBeforeTheNodeRuns; M6 awaitSection replies nil without taking fails RemovedDeviceTakesARulePreset; M7 a stopped node stores nothing fails TheDevicesOwnRulesAreKept; M8 the runner shows the preset and replies before the engine has it fails RulePresetIsStoredByTheService and SetBeforeTheNodeRuns; M9 the idle take never shows the stored preset fails RemovedDeviceTakesARulePreset.
- 2026-11-14 docs: internal/agent/doc.go (how a preset is taken) and docs/design/configuration.md "When a change takes effect" (rule preset row).
- 2026-11-14 merged rewrite twice (d2a4793 in 2f6622c, 16b2f25 in 32e2176), no conflicts.
- 2026-11-15 ran on 32e2176: full make lab-test green (lab and every package in a lab node, internal/agent included; GOFLAGS=-p=2 LAB_P=1); make lint green; make test red only on TestResolvConfAFileRenamedInIsTakenAtOnce (internal/dataplane/dns, "not taken back" at the 5 s limit), which this branch doesn't touch: it also failed on 2f6622c (3 of 3 with -count=3) and on rewrite 16b2f25 alone; the dns package passed in the lab node. Same flake TP-208 was merged with (TP-217's area); the make test box stays open for the orchestrator to accept it. Earlier the full lab was also green on 2f6622c.
- 2026-11-15 out of scope: setToggle (kill switch, allow-LAN) has the same stored-and-shown-before-acted order; its killSwitchReapply tick re-applies it, so it self-heals, but Status's kill-switch On can lead the firewall for up to one tick when the caller's ctx ends first.
- 2026-11-15 couldn't verify: nothing device-only; the change is platform-independent agent code, covered by unit tests and the lab.
