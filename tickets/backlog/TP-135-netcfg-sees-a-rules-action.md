---
id: TP-135
title: "netcfg: the configurator sees a policy rule's action"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: [TP-091]
refs: [docs/design/routing.md#route-table]
owner: ""
branch: ""
---

## Goal
The Linux configurator's check of its own policy rules notices an owner's rule that someone turned into `blackhole`, `prohibit` or `unreachable`, and puts it back, as it does for any other change.

## Scope
- `ruleOf` (`netcfg/rules_linux.go`) says it rejects "another … action", but vishvananda/netlink's rule dump never fills the rule type, so it can't see one: a rule changed from lookup to blackhole looks like the configurator's own and stays.
- TP-091 reads rules from a raw `RTM_GETRULE` dump that carries the action (`dumpRules`/`parseRawRule`), and (after its round 3) one shared judge of "a plain rule" (`plainRule`) for the mask, suppress and action rules. Read the configurator's survey through `dumpRules`/`parseRawRule` too, so a changed action counts as foreign and is repaired, and the list of selectors netcfg never sets exists once: `ruleOf` (and its netlink.Rule field list) goes.
- Say in the netcfg doc what the survey compares.

## Acceptance
- [ ] lab: an owner's lookup rule replaced by `ip rule add … blackhole` at the same priority and protocol is put back by the next apply, and a test fails if the action isn't read
- [ ] one list of the selectors netcfg never sets: `ruleOf` is gone, and the configurator and diagnostics both read rules through `parseRawRule`
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- From TP-091's round-3 and round-4 design reviews (2026-10-23). Predates TP-091.
- **Slot (pre-M2 phase, 2026-10-24).** Wave 1, macOS lane.

## Log
- 2026-10-23 created in backlog (TP-091 review round 3)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, macOS)
