---
id: TP-135
title: "netcfg: the configurator sees a policy rule's action"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: [TP-091]
refs: [docs/design/routing.md#route-table]
owner: "agent-tp-135"
branch: "tp-135-netcfg-sees-a-rules-action"
---

## Goal
The Linux configurator's check of its own policy rules notices an owner's rule that someone turned into `blackhole`, `prohibit` or `unreachable`, and puts it back, as it does for any other change.

## Scope
- `ruleOf` (`netcfg/rules_linux.go`) says it rejects "another … action", but vishvananda/netlink's rule dump never fills the rule type, so it can't see one: a rule changed from lookup to blackhole looks like the configurator's own and stays.
- TP-091 reads rules from a raw `RTM_GETRULE` dump that carries the action (`dumpRules`/`parseRawRule`), and (after its round 3) one shared judge of "a plain rule" (`plainRule`) for the mask, suppress and action rules. Read the configurator's survey through `dumpRules`/`parseRawRule` too, so a changed action counts as foreign and is repaired, and the list of selectors netcfg never sets exists once: `ruleOf` (and its netlink.Rule field list) goes.
- Say in the netcfg doc what the survey compares.

## Acceptance
- [x] lab: an owner's lookup rule replaced by `ip rule add … blackhole` at the same priority and protocol is put back by the next apply, and a test fails if the action isn't read
- [x] one list of the selectors netcfg never sets: `ruleOf` is gone, and the configurator and diagnostics both read rules through `parseRawRule`
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- From TP-091's round-3 and round-4 design reviews (2026-10-23). Predates TP-091.
- **Slot (pre-M2 phase, 2026-10-24).** Wave 1, macOS lane.

## Log
- 2026-10-23 created in backlog (TP-091 review round 3)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, macOS)
- 2026-10-28 backlog → in-progress, owner: agent-tp-135
- 2026-10-28 done: the configurator's rule survey (`ownKernelRules`), its old-kernel stray check and `Survey`'s foreign rules read the raw dump (`dumpBothRules` → `parseRawRule`, shared with `Inspect`); `asRule` maps a HostRule to a Rule and judges it with `plainRule(hr, hr.Action)`; `ruleOf`, `listRules` and `ownAndForeignRules` are gone. Deletes (reconcile, Close, strays) and their undo send the dumped message back (`ruleRequest`: RTM_DELRULE / RTM_NEWRULE, report-only flags cleared), so the kernel removes exactly that rule and an undo restores it with its action (before, an undo re-added a deleted rule as a lookup). Sockets open in the configurator's namespace, or the calling thread's for the current one, as the handle was. netcfg doc says what the survey compares
- 2026-10-28 tests: new lab `TestApplyRepairsARuleWhoseActionChanged` (lookup at 5299 replaced by a blackhole, same priority, destination and protocol: an Apply cancelled once the blackhole went puts it back, the next Apply puts the lookup back, Close removes it). `TestStrayRulesFindRulesThatLostTheirProtocol` builds raw rules instead of netlink.Rules because `strayRules` now takes them (same cases and asserts). Mutations, each caught: `asRule` ignoring the action (`plainRule(hr, "")`); the delete sending lookup as the action; the undo not re-adding the rule
- 2026-10-28 ran: `make lint`, `make test`, `make lab-gotest PKG=./internal/dataplane/netcfg/...` and the full `make lab-test` green on e70e319. Not verified: clearing the detached/unresolved flags before a re-add (no test makes a rule with a detached oif and then undoes its delete); retries for an interrupted dump drop from 5 to `dumpRules`' 3
- 2026-10-28 in-progress → review
