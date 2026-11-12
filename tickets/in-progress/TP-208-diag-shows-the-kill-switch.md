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
- For TP-029's checklist, `sudo thinkpol diag` (root: it is a host part) has `kill_switch` beside `guard`, quotable by JSON path: `kill_switch.where` ("pf anchor com.apple/001.thinkpol-killswitch"), `kill_switch.present`, `kill_switch.rules.rules[].text` (pfctl's lines, in order, with `packets`, `evaluations`), `kill_switch.sets.sets[]` (`thinkpol_killswitch` and `thinkpol_killswitch_nodns` with their `entries`), `kill_switch.pf.enabled.enabled`, `kill_switch.pf.reference` (`recorded`, `pid`, `held`). With the switch off: `present` false, no rules or sets.

## Log
- 2026-11-12 created in backlog (from TP-048's review)
- 2026-11-12 backlog → in-progress, owner: agent-tp-208
- 2026-11-12 firewall.InspectKillSwitch (Linux: table, chains, rules with counters, set sizes; macOS: anchor rules with counters, table sizes, pf enabled, its own reference); the guard's readers shared (readTable, inspectRules, pfEnabler.inspectReference); `ct direction` rendered. Diagnostics.KillSwitch, Inspector.KillSwitch, DiagKillSwitch (field 15, no schema bump: added), docs (firewall, localapi, desktop-client, api-overview-reference)
- 2026-11-12 acceptance split: the macOS box's unit-test half ticked; its device half (diag in TP-029's session) is a separate box, open, for the owner's run
- 2026-11-12 mutations, each failed its test and was restored: Linux set size counting interval ends (TestInspectReadsTheKillSwitchAsTheKernelHoldsIt, and in the lab TestKillSwitchUnderSystemd: diag's sizes vs nft -j); `ct` unrendered (Linux unit); macOS missing table as unreadable, the guard's record read for the reference, pf enabled dropped (TestInspectReadsTheKillSwitchAsPfListsIt); root's snapshot without the kill switch (TestTheHostPartsAreRoots); presence always sent, an unreadable set keeping its size (TestDiagnoseCarriesTheKillSwitch)
- 2026-11-12 ran: lab-gotest ./internal/dataplane/firewall (Inspect) pass; lab-gotest ./lab TestKillSwitchUnderSystemd pass (178 s); make lint, make test green after merging rewrite at 5742584
- 2026-11-12 not verified: the macOS reading on a real Mac (fake pfctl only; TP-029). Out of scope: TP-117's TestResolvConfRestoreAfterARewriteFailedPartwayPutsBackTheWholeOriginal failed once in make test under load ("not cut inside the original"), passed 5/5 alone and on the rerun
