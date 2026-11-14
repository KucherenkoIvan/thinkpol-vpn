---
id: TP-208
title: "`thinkpol diag` shows the kill switch's table or anchor"
milestone: M2
area: agent
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-048, TP-091]
refs: [D4, docs/design/desktop-client.md#the-local-api]
needs_human: macos
owner: agent-tp-208
branch: tp-208-diag-shows-the-kill-switch
---

## Goal
`thinkpol diag` shows what the kill switch holds on the host (the nftables table on Linux, the pf anchor and its tables on macOS) beside the leak guard's section, so a member's report says whether it was in place and what it let out.

## Scope
- `firewall.InspectKillSwitch` per OS, after `InspectIPv6Guard`'s pattern: present or not, its chains or rules, the sizes of its sets or tables, pf's enable state and the kill switch's reference on macOS.
- A diag section and its render; the local API doc.

## Out of scope
- Changing what the kill switch does.

## Acceptance
- [x] Linux: diag in the lab shows the table with the kill switch on and none with it off (lab test, mutation-checked)
- [x] macOS: the inspection read from the fake pfctl (unit test)
- [ ] macOS: diag's output in TP-029's device session

## Notes
- Milestone M2: cheap, since the guard's inspector is the template, and the M2 acceptance device session (TP-029) checks the macOS kill switch: the diag output is its evidence.
- From TP-048's review (open since round 2).
- For TP-029's checklist, `sudo thinkpol diag` (root: it is a host part) has `kill_switch` beside `guard`, quotable by JSON path: `kill_switch.where` ("pf anchor com.apple/001.thinkpol-killswitch"), `kill_switch.present`, `kill_switch.rules.rules[].text` (pfctl's lines, in order, with `packets`, `evaluations`), `kill_switch.sets.sets[]` (`thinkpol_killswitch` and `thinkpol_killswitch_nodns` with their `entries`), `kill_switch.pf.enabled.enabled`, `kill_switch.pf.reference` (`recorded`, `pid`, `held`). With the switch off: `present` false, no rules or sets (unverified on a Mac: what `pfctl -a <anchor> -s rules -v` prints for a missing anchor; the off state may read as `present` left out, unknown, rather than false). Read the kill switch's section together with `guard.pf.guard_check` and `guard.pf.skipped`: a main ruleset without `anchor "com.apple/*"` leaves the anchor loaded, so `kill_switch.present`, `kill_switch.pf.enabled.enabled` and `kill_switch.pf.reference.held` all read true while pf evaluates nothing in it, and only `guard_check` ("missing") shows that; anchors sorting between `000.thinkpol` and `001.thinkpol-killswitch` are listed nowhere. Rule texts quote real addresses (the direct DNS upstreams in `kill_switch.rules.rules[].text`; an unparsable table's entry in its `unreadable`): redact every address before anything from it goes into a ticket.

## Review findings
- [x] R1.1 (should-fix) the TP-029 checklist note: read the kill switch with `guard.pf.guard_check` and `guard.pf.skipped` (an unhooked anchor reads present, enabled and held); redact addresses in rule texts and unreadable texts; the missing anchor's reading unverified on a Mac
- [x] R1.2 (should-fix) stale docs and comments: (a) localapi doc.go and localapi.proto, a guard's or a kill switch's `present`; (b) doc.go, a pf reference's token stays in its owner's record; (c) api-overview-reference.md, kill_switch in the group's sample, five host parts; (d) routetable/inspect.go's shared types say the guard's or the kill switch's
- [x] R1.3 (nit) (a) the not-regular record's error names its owner; (b) localapi.proto declares kill_switch beside guard (number 15 kept); (c) diagnose_test's not-root failure prints d.KillSwitch
- [x] R1.4 (note) TP-117's TestResolvConfRestoreAfterARewriteFailedPartwayPutsBackTheWholeOriginal failed once under load; the orchestrator files it

## Log
- 2026-11-12 created in backlog (from TP-048's review)
- 2026-11-12 backlog → in-progress, owner: agent-tp-208
- 2026-11-12 firewall.InspectKillSwitch (Linux: table, chains, rules with counters, set sizes; macOS: anchor rules with counters, table sizes, pf enabled, its own reference); the guard's readers shared (readTable, inspectRules, pfEnabler.inspectReference); `ct direction` rendered. Diagnostics.KillSwitch, Inspector.KillSwitch, DiagKillSwitch (field 15, no schema bump: added), docs (firewall, localapi, desktop-client, api-overview-reference)
- 2026-11-12 acceptance split: the macOS box's unit-test half ticked; its device half (diag in TP-029's session) is a separate box, open, for the owner's run
- 2026-11-12 mutations, each failed its test and was restored: Linux set size counting interval ends (TestInspectReadsTheKillSwitchAsTheKernelHoldsIt, and in the lab TestKillSwitchUnderSystemd: diag's sizes vs nft -j); `ct` unrendered (Linux unit); macOS missing table as unreadable, the guard's record read for the reference, pf enabled dropped (TestInspectReadsTheKillSwitchAsPfListsIt); root's snapshot without the kill switch (TestTheHostPartsAreRoots); presence always sent, an unreadable set keeping its size (TestDiagnoseCarriesTheKillSwitch)
- 2026-11-12 ran: lab-gotest ./internal/dataplane/firewall (Inspect) pass; lab-gotest ./lab TestKillSwitchUnderSystemd pass (178 s); make lint, make test green after merging rewrite at 5742584
- 2026-11-12 not verified: the macOS reading on a real Mac (fake pfctl only; TP-029). Out of scope: TP-117's TestResolvConfRestoreAfterARewriteFailedPartwayPutsBackTheWholeOriginal failed once in make test under load ("not cut inside the original"), passed 5/5 alone and on the rerun
- 2026-11-12 full make lab-test green on 13b6bc0 (lab and every package in a lab node, GOFLAGS=-p=2 LAB_P=1)
- 2026-11-12 in-progress → review
- 2026-11-12 review round 1: no code defect; docs and nits R1.1–R1.4
- 2026-11-12 R1.1–R1.3 done in e490335 (R1.4 is the orchestrator's); also DiagGuardRule's proto comment names the kill switch. Mutations, each failed its test and was restored: the proto's old field order (TestDiagnoseServesAVersionedSnapshot: kill_switch not beside guard); the record error naming the guard for any owner (TestInspectReadsTheRecordWithoutQuotingIt)
- 2026-11-12 ran on e490335: make lint, make test green; lab-gotest ./internal/dataplane/firewall pass; full make lab-test twice, both red only on TestAnExitThatNeverHandshakesIsExitNoHandshake (internal/agent, TP-195's), everything else green
- 2026-11-12 out of scope: TestAnExitThatNeverHandshakesIsExitNoHandshake is flaky in a lab node: COUNT=5 failed 2/5 on e490335 and 1/5 on rewrite 495b270 (without this branch); failing runs end in 1.3-3.9 s at status_test.go:1095 (down, exit_no_handshake, no handshake yet), passing ones take ~9 s. Not merged: the merge was conditional on a green PART 1
- 2026-11-14 merged rewrite d2a4793 (TP-134, TP-210, the board's new tickets) in df935d4, no conflicts; diag and `thinkpol rollback` read and remove the same kill switch (both through firewall.NewKillSwitch: the nftables table, the pf anchor)
- 2026-11-14 ran on df935d4: full make lab-test green (lab and every package in a lab node, GOFLAGS=-p=2 LAB_P=1); make lint green; make test red only on TestResolvConfAFileRenamedInIsTakenAtOnce (internal/dataplane/dns, resolvconf_settle_test.go:307, "not taken back", at the 5 s limit), failed again 2/5 with -count=5 on df935d4 and 2/5 on rewrite d2a4793 without this branch; everything else green
- 2026-11-14 out of scope: TestResolvConfAFileRenamedInIsTakenAtOnce is flaky under load on Linux (no ticket names it; passing runs take ~0.2 s, failing ones hit the 5 s limit). Not merged: the merge was conditional on a green PART 1; handoff: merge once the orchestrator calls it a known flake or it is fixed
