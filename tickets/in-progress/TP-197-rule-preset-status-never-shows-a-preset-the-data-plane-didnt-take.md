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
- [x] `make lint`, `make test` pass (lint green; test green but for the rewrite flake TestResolvConfAFileRenamedInIsTakenAtOnce, which TP-217 fixes; accepted by the orchestrator, see the Log)

## Notes
- From TP-166's delta check, 2026-11-07.
- Safety-adjacent: a member could believe all traffic goes through the tunnel while some goes direct.

## Review findings
Review round 1 (go-paranoid, go-style), accepted by the orchestrator. The design (status and device.json change only once the data plane has taken the preset) is accepted.
- [x] R1.1 (blocker) a layout failure after Engine.SetRules (change() failing in routes.around) leaves the router on the old preset while status and device.json show the new one as enforced, and nothing retries: retry on any SetRules error but ErrPresetUnavailable; never report a preset enforced until the engine's routedRules.Preset matches it (status: not enforced yet, retrying, with the reason); SetRulePreset returns a distinct error (ErrPresetNotEnforced) wrapping the cause, mapped in localapi to its own refusal code; test with an injected layout failure that converges once it clears; correct the Log line about the route table.
- [x] R1.2 (should-fix) no test makes the store fail: add tests for a store failure on the idle path (takeIdle) and on the running path (takeRules).
- [x] R1.3 (should-fix) M8's failure is timing-dependent: catch it deterministically, or prove it with -count=50.
- [x] R1.4 (should-fix) a caller whose ctx ends after the node took the request gets DeadlineExceeded for a change that happened: once taken, report the outcome; argue the bound in a comment; test.
- [x] R1.5 (nit) presetMu.Lock() ignores the caller's ctx: make the wait respect it; test.
- [x] R1.6 (should-fix, docs) doc.go and docs/design/configuration.md: with no data plane running, the preset is stored and shown, and the next start takes it; drop the "(TP-197)" reference; document the not-enforced-yet state and its refusal code.
- [x] R1.7 (should-fix, ticket) the make test box: log the accepted dns flake (TP-217 fixes it) and tick it.
- [x] R1.8 (nit) TestARulePresetSetBeforeTheNodeRunsIsTaken polls presetMu.TryLock(): wait on something a caller can observe.

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
- 2026-11-15 in-progress → review
- 2026-11-15 review → has-errors (round 1 findings R1.1–R1.8)
- 2026-11-15 correction to the 2026-11-14 design line: "an engine whose route table fails after SetRules still follows the new rules" holds only when the route table's growth fails (after setTable); when the layout itself fails (change() inside routes.around: removing devices, NewEgress, SetPeers, SetMTU, wg.Configure, router.SetTable) the router stays on the previous rules. R1.1 handles that case.
- 2026-11-15 R1.1: Status.RulesEnforced is set only while the engine's routed preset (dataplane.RuleStatus.Preset) is the stored one, and PresetUnavailable only then; otherwise Health has the new problem rule_preset_not_enforced and the CLI says "(not enforced yet: laying out its routes failed, retrying)". The runner's layOutRules sets retryAt and rulesPending on any SetRules error but ErrPresetUnavailable; the retry applies the section, then hands the rules over again (never the other way round, so revocations don't wait). SetRulePreset returns agent.ErrPresetNotEnforced wrapping the cause; localapi maps it to the refusal rule_preset_not_enforced (codes.Unavailable). A test seam, tuning.setRules, stands in for Engine.SetRules: no layout failure is reachable from the agent's tests otherwise.
- 2026-11-15 for the orchestrator: the new refusal code is rule_preset_not_enforced (localapi.ErrPresetNotEnforced); whichever of TP-167 and TP-197 merges second adds its exit-code entry (exit 1 with the status).
- 2026-11-15 R1.2-R1.5, R1.8 tests: TestARulePresetWhoseLayoutFailsIsRetried (R1.1), TestARulePresetStoreThatFailsChangesNothing (running) and TestARulePresetStoreThatFailsWhileStoppedChangesNothing (idle; a directory takes the store's temporary file name, which fails for root too), TestARulePresetIsShownOnceTheEngineHasIt (R1.3), TestARulePresetCallerThatGivesUpAfterTheTakeHearsTheOutcome (R1.4), TestASecondRulePresetCallGivesUpOnItsCtx (R1.5; presetMu became the one-slot channel presetTurn, waited for under the ctx); TestARulePresetSetBeforeTheNodeRunsIsTaken no longer polls presetMu.TryLock(): for 100 ms while SetRulePreset hasn't returned, nothing shows the preset (R1.8). localapi: TestTheRulePresetLineSaysWhetherItIsEnforced; the refusal in TestTheCLIControlsTheNode and TestRefusalWording.
- 2026-11-15 mutations, each failing the named test and restored: MA layOutRules sets no retryAt fails WhoseLayoutFailsIsRetried; MB RulesEnforced set whenever an engine runs (the report regardless) fails WhoseLayoutFailsIsRetried; MI the apply after a failed layout never hands the rules over again fails WhoseLayoutFailsIsRetried (never converges); MC takeIdle sets the report before checking take's error, and MD takeIdle ignores take's error, fail StoreThatFailsWhileStoppedChangesNothing; ME takeRules carries on with rules.Local{} after take fails fails StoreThatFailsChangesNothing; M8 the runner shows the preset and replies before the engine has it fails IsShownOnceTheEngineHasIt (20 of 20 with -count=20: checked at the engine call, from the Status read there, no timing), plus RulePresetIsStoredByTheService and three others; MG the wait after the take ends with the caller's ctx fails CallerThatGivesUpAfterTheTakeHearsTheOutcome; MH presetTurn taken without the ctx fails SecondRulePresetCallGivesUpOnItsCtx. Unmutated, the preset tests passed -count=20 and -race -count=3.
- 2026-11-15 R1.4: once taken, SetRulePreset waits for the reply without its ctx; node.go's comment argues the bound (every receiver replies in the same step, after a file write and one Engine.SetRules).
- 2026-11-15 R1.6 docs: internal/agent/doc.go (no data plane running: stored and shown for the next start; the not-enforced-yet state, its problem and error), docs/design/configuration.md (same, refusal code, "(TP-197)" dropped), and also docs/design/api-overview-reference.md (problem vocabulary, SetRulePreset's refusals, the refusal table, rules_enforced), which the brief's file list didn't name but the change makes stale.
- 2026-11-15 merged rewrite (d191d00) in 9a2d38d, no conflicts.
- 2026-11-15 ran on 9a2d38d: make lint green; make test red only on TestResolvConfAFileRenamedInIsTakenAtOnce (internal/dataplane/dns), with umask 022; full make lab-test green (lab and 39 packages in a lab node, internal/agent and internal/dataplane/dns included; GOFLAGS=-p=2 LAB_P=1).
- 2026-11-15 make test's only failure, TestResolvConfAFileRenamedInIsTakenAtOnce, is a flake on rewrite too, in code this branch doesn't touch; the orchestrator accepts it (TP-217 fixes it)
- 2026-11-15 out of scope: proto/thinkpol/localapi/v1/localapi.proto's SetRulePreset comment lists its refusals without rule_preset_not_enforced (proto left alone to keep the merge with TP-167 small; it needs make proto); ReloadRules (new lists) failing in its layout is only logged, not retried, as before this branch (the preset stays the same, so status is not wrong about it).
- 2026-11-15 couldn't verify: nothing device-only; platform-independent agent code, covered by unit tests and the lab.
- 2026-11-15 has-errors → in-progress (round 1 findings R1.1–R1.8 picked up)
