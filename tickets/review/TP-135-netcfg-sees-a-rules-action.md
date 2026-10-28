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
Round 1 (2026-10-28): correctness (paranoid), design (torvalds) and conventions (go-style) reviews, and the cross-family review (Cursor), folded in late: its fix-first (New's rule dumps and deletes follow the calling thread's namespace while the handle stays in New's) is R1.2; its nits are R1.12 and R1.13.
- [x] R1.1 (paranoid #1, blocker) A kernel without IPv6 rules (ipv6.disable=1, CONFIG_IPV6_MULTIPLE_TABLES=n) sends EAFNOSUPPORT in the dump's NLMSG_DONE, and `dumpDone` makes it a hard error: every Apply, Close and Survey fails. Treat it as an empty family in `dumpDone`, which Inspect shares; add the TestDumpDone case.
- [x] R1.2 (paranoid #2, torvalds #1) Rule sockets for "the current namespace" open in whatever namespace the calling thread is in at each call, and NewInNamespace's setns on every rule operation. Open one rule socket in newLinux on the locked thread, keep it (c.mu serialises its use), close it in Close; correct the Log's "as the handle was".
- [x] R1.3 (paranoid #3) doc.go ("the kernel removes exactly that rule") and the request's comment ("matches a delete on every attribute") promise more than rule_find gives (zero fields are wildcards, flags and goto aren't compared, the first match in list order wins). Say what is guaranteed; a RESIDUAL-RISKS row if the residual is real for valid configs.
- [x] R1.4 (torvalds #3) A rule just added that doesn't read back as a Rule netcfg could add (an attribute a kernel reports on every rule that parseRawRule doesn't read) is deleted and re-added on every Apply, silently. Use checkRuleProtocol's re-dump to fail loudly instead.
- [x] R1.5 (torvalds #4) `plainRule`'s action parameter uses "" as a "don't check" flag. Drop it; asRule checks Other and the action.
- [x] R1.6 (torvalds #5) The configurator's raw codec (rawRule, the dump, parse, request, actionName) lives in inspect_linux.go. Move it to rawrule_linux.go.
- [x] R1.7 (go-style #3, torvalds #6) The delete's undo and the old-kernel stray delete return bare errnos. Wrap them.
- [x] R1.8 (go-style #1, #2) Comments now false: `NewInNamespaceToKill` (the kill no longer reaches the rule sockets), the `ns`/`rulesNS` field comments and newLinux's "Watch subscribes" line.
- [x] R1.9 (torvalds #2, paranoid nit) The add's undo goes through `c.h.RuleDel`, which sends action 0 and deletes by selector whatever the action. Add rules raw (ruleMsg) and undo with the same bytes; `toNetlinkRule` goes; a ruleMsg round-trip unit test.
- [x] R1.10 (torvalds #7-#12) Nits: inspectWith's partly built configurator (rulesNS zero value is fd 0); isOwnerProtocol through ownerOf; one dumpRetries const; a fibRuleHdrLen const and a length check before the flags are cleared; Other set once, visibly; one type for the protocol.
- [x] R1.11 (go-style #4-#8) Nits: names (ruleDumpTimeout bounds requests too, dumpBothRules, ruleRequest); the TP-135 history comment in rules_internal_linux_test.go; one rule format (%v) in errors.
- [x] R1.12 (cross-family nit #3) The rule dump's retries for an interrupted dump dropped from listRules' 5 to dumpRules' 3. Use one constant, the larger.
- [x] R1.13 (cross-family nit #4) The lab test of action repair covers IPv4 only. Add IPv6 if cheap.

## Log
- 2026-10-23 created in backlog (TP-091 review round 3)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, macOS)
- 2026-10-28 backlog → in-progress, owner: agent-tp-135
- 2026-10-28 done: the configurator's rule survey (`ownKernelRules`), its old-kernel stray check and `Survey`'s foreign rules read the raw dump (`dumpBothRules` → `parseRawRule`, shared with `Inspect`); `asRule` maps a HostRule to a Rule and judges it with `plainRule(hr, hr.Action)`; `ruleOf`, `listRules` and `ownAndForeignRules` are gone. Deletes (reconcile, Close, strays) and their undo send the dumped message back (`ruleRequest`: RTM_DELRULE / RTM_NEWRULE, report-only flags cleared), so the kernel removes exactly that rule and an undo restores it with its action (before, an undo re-added a deleted rule as a lookup). Sockets open in the configurator's namespace, or the calling thread's for the current one, as the handle was. netcfg doc says what the survey compares
- 2026-10-28 tests: new lab `TestApplyRepairsARuleWhoseActionChanged` (lookup at 5299 replaced by a blackhole, same priority, destination and protocol: an Apply cancelled once the blackhole went puts it back, the next Apply puts the lookup back, Close removes it). `TestStrayRulesFindRulesThatLostTheirProtocol` builds raw rules instead of netlink.Rules because `strayRules` now takes them (same cases and asserts). Mutations, each caught: `asRule` ignoring the action (`plainRule(hr, "")`); the delete sending lookup as the action; the undo not re-adding the rule
- 2026-10-28 ran: `make lint`, `make test`, `make lab-gotest PKG=./internal/dataplane/netcfg/...` and the full `make lab-test` green on e70e319. Not verified: clearing the detached/unresolved flags before a re-add (no test makes a rule with a detached oif and then undoes its delete); retries for an interrupted dump drop from 5 to `dumpRules`' 3
- 2026-10-28 in-progress → review
- 2026-10-28 review → has-errors (round 1: R1.1–R1.11)
- 2026-10-28 has-errors → in-progress (round 1 findings)
- 2026-10-28 round 1 fixed (WIP 9487d1e by the first fixer, finished on takeover): the raw codec (rawRule, the dump, parseRawRule, ruleMsg, sendRule, actionName) moved to `rawrule_linux.go`; dumps go through the netlink library's ExecuteIter, which reads the errno of NLMSG_DONE as of NLMSG_ERROR, and `dumpErr` takes EAFNOSUPPORT as a family with no rules (R1.1). One rule socket opened in `newLinux` beside the handle, kept and closed by Close, so rule dumps and requests stay in the configurator's namespace whatever thread calls (R1.2): the round-1 Log's "as the handle was" was untrue, per-call sockets followed the calling thread for `New` and setns'd on every operation for `NewInNamespace`. doc.go, `sendRule` and RR53 say what a delete matches (first rule that matches every field the message sets; absent selectors and invert are wildcards) (R1.3). `checkAddedRules`/`judgeAdded` fail with `errNotReadBack` when a rule just added doesn't read back as added (R1.4). `plainRule` has no action parameter; `asRule` checks Other and the action (R1.5). Undo and stray-delete errors wrapped (R1.7); comments corrected (R1.8). Adds are raw (`ruleMsg`), undone with the same bytes; `toNetlinkRule` gone (R1.9). Nits: `inspectIn` builds no partial configurator, `listRoutes` is a function of the handle, `isOwnerProtocol` through `ownerOf`, `fibRuleHdrLen` and a length check in `sendRule`, Other set once (`unknown`), `rawRule.protocol` a RouteProtocol (R1.10); `ruleSocketTimeout`, `dumpAllRules`, `sendRule`, no TP history comment, `%v` for rules in every error (R1.11); one `dumpRetries` = 5 for routes, addresses and rules (R1.12); the action-repair lab test runs for IPv4 and IPv6 (R1.13)
- 2026-10-28 tests: new `TestDumpErr` (replaces TestDumpDone, EAFNOSUPPORT case), `TestRuleMsgReadsBackAsTheRule`, `TestJudgeAddedFailsARuleThatDoesNotReadBack`; `TestApplyRepairsARuleWhoseActionChanged` gains an IPv6 subtest. Mutations, each caught in one lab run: `dumpErr` failing on EAFNOSUPPORT (TestDumpErr); `ruleMsg` sending a mark without FRA_FWMASK (TestRuleMsgReadsBackAsTheRule, both mark cases); `judgeAdded` skipping the read-back check (TestJudgeAdded…); `asRule` ignoring the action (TestApplyRepairs…/IPv4 and /IPv6)
- 2026-10-28 ran: merged origin/rewrite (6d99046); `make lint`, `make test` and the full `make lab-test` (36 packages) green on 6d99046. Not verified: the `New` (current namespace) path in the lab (every netcfg lab test uses NewInNamespace); EAFNOSUPPORT from a real kernel without IPv6 rules (the lab kernel has them; `dumpErr` is unit-tested and the library's NLMSG_DONE handling read from source); clearing the detached/unresolved flags before a re-add
- 2026-10-28 out of scope, for the orchestrator: a Rule with a /0 destination passes Validate but the kernel stores no destination, so since R1.4 its Apply fails with errNotReadBack (before, it was replaced on every Apply); the kernel's rule_exists ignores flags and an absent Dst, so an add can report a misleading ErrConflict for pairs Validate allows; a changed action could be repaired add-before-delete (no window without the rule)
- 2026-10-28 in-progress → review
