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
owner: ""
branch: ""
---

## Goal
`thinkpol diag` shows what the kill switch holds on the host (the nftables table on Linux, the pf anchor and its tables on macOS) beside the leak guard's section, so a member's report says whether it was in place and what it let out.

## Scope
- `firewall.InspectKillSwitch` per OS, after `InspectIPv6Guard`'s pattern: present or not, its chains or rules, the sizes of its sets or tables, pf's enable state and the kill switch's reference on macOS.
- A diag section and its render; the local API doc.

## Out of scope
- Changing what the kill switch does.

## Acceptance
- [ ] Linux: diag in the lab shows the table with the kill switch on and none with it off (lab test, mutation-checked)
- [ ] macOS: the inspection read from the fake pfctl (unit test); diag's output in TP-029's device session

## Notes
- Milestone M2: cheap, since the guard's inspector is the template, and the M2 acceptance device session (TP-029) checks the macOS kill switch: the diag output is its evidence.
- From TP-048's review (open since round 2).

## Log
- 2026-11-12 created in backlog (from TP-048's review)
