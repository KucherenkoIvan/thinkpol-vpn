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

## Review findings
Round 1 (2026-10-28): correctness (paranoid), design (torvalds) and conventions (go-style) reviews; the cross-family review was still empty and goes to round 2.
- [ ] R1.1 (paranoid #1, blocker) A kernel without IPv6 rules (ipv6.disable=1, CONFIG_IPV6_MULTIPLE_TABLES=n) sends EAFNOSUPPORT in the dump's NLMSG_DONE, and `dumpDone` makes it a hard error: every Apply, Close and Survey fails. Treat it as an empty family in `dumpDone`, which Inspect shares; add the TestDumpDone case.
- [ ] R1.2 (paranoid #2, torvalds #1) Rule sockets for "the current namespace" open in whatever namespace the calling thread is in at each call, and NewInNamespace's setns on every rule operation. Open one rule socket in newLinux on the locked thread, keep it (c.mu serialises its use), close it in Close; correct the Log's "as the handle was".
- [ ] R1.3 (paranoid #3) doc.go ("the kernel removes exactly that rule") and the request's comment ("matches a delete on every attribute") promise more than rule_find gives (zero fields are wildcards, flags and goto aren't compared, the first match in list order wins). Say what is guaranteed; a RESIDUAL-RISKS row if the residual is real for valid configs.
- [ ] R1.4 (torvalds #3) A rule just added that doesn't read back as a Rule netcfg could add (an attribute a kernel reports on every rule that parseRawRule doesn't read) is deleted and re-added on every Apply, silently. Use checkRuleProtocol's re-dump to fail loudly instead.
- [ ] R1.5 (torvalds #4) `plainRule`'s action parameter uses "" as a "don't check" flag. Drop it; asRule checks Other and the action.
- [ ] R1.6 (torvalds #5) The configurator's raw codec (rawRule, the dump, parse, request, actionName) lives in inspect_linux.go. Move it to rawrule_linux.go.
- [ ] R1.7 (go-style #3, torvalds #6) The delete's undo and the old-kernel stray delete return bare errnos. Wrap them.
- [ ] R1.8 (go-style #1, #2) Comments now false: `NewInNamespaceToKill` (the kill no longer reaches the rule sockets), the `ns`/`rulesNS` field comments and newLinux's "Watch subscribes" line.
- [ ] R1.9 (torvalds #2, paranoid nit) The add's undo goes through `c.h.RuleDel`, which sends action 0 and deletes by selector whatever the action. Add rules raw (ruleMsg) and undo with the same bytes; `toNetlinkRule` goes; a ruleMsg round-trip unit test.
- [ ] R1.10 (torvalds #7-#12) Nits: inspectWith's partly built configurator (rulesNS zero value is fd 0); isOwnerProtocol through ownerOf; one dumpRetries const; a fibRuleHdrLen const and a length check before the flags are cleared; Other set once, visibly; one type for the protocol.
- [ ] R1.11 (go-style #4-#8) Nits: names (ruleDumpTimeout bounds requests too, dumpBothRules, ruleRequest); the TP-135 history comment in rules_internal_linux_test.go; one rule format (%v) in errors.

## Log
- 2026-10-23 created in backlog (TP-091 review round 3)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, macOS)
- 2026-10-28 backlog → in-progress, owner: agent-tp-135
- 2026-10-28 done: the configurator's rule survey (`ownKernelRules`), its old-kernel stray check and `Survey`'s foreign rules read the raw dump (`dumpBothRules` → `parseRawRule`, shared with `Inspect`); `asRule` maps a HostRule to a Rule and judges it with `plainRule(hr, hr.Action)`; `ruleOf`, `listRules` and `ownAndForeignRules` are gone. Deletes (reconcile, Close, strays) and their undo send the dumped message back (`ruleRequest`: RTM_DELRULE / RTM_NEWRULE, report-only flags cleared), so the kernel removes exactly that rule and an undo restores it with its action (before, an undo re-added a deleted rule as a lookup). Sockets open in the configurator's namespace, or the calling thread's for the current one, as the handle was. netcfg doc says what the survey compares
- 2026-10-28 tests: new lab `TestApplyRepairsARuleWhoseActionChanged` (lookup at 5299 replaced by a blackhole, same priority, destination and protocol: an Apply cancelled once the blackhole went puts it back, the next Apply puts the lookup back, Close removes it). `TestStrayRulesFindRulesThatLostTheirProtocol` builds raw rules instead of netlink.Rules because `strayRules` now takes them (same cases and asserts). Mutations, each caught: `asRule` ignoring the action (`plainRule(hr, "")`); the delete sending lookup as the action; the undo not re-adding the rule
- 2026-10-28 ran: `make lint`, `make test`, `make lab-gotest PKG=./internal/dataplane/netcfg/...` and the full `make lab-test` green on e70e319. Not verified: clearing the detached/unresolved flags before a re-add (no test makes a rule with a detached oif and then undoes its delete); retries for an interrupted dump drop from 5 to `dumpRules`' 3
- 2026-10-28 in-progress → review
- 2026-10-28 review → has-errors (round 1: R1.1–R1.11)
