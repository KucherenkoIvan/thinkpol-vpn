---
id: TP-150
title: "netcfg (Linux rules): an honest conflict error, and action repair that adds first"
milestone: M2
area: dataplane/netcfg
repo: thinkpol-vpn
size: S
depends_on: [TP-135]
refs: []
owner: ""
branch: ""
---

## Goal
Two rough edges of netcfg's Linux rules after TP-135: an add that the kernel refuses as a duplicate says what collided, and repairing a rule whose action changed never leaves a moment without the rule.

## Scope
- **(a) Duplicates.** The kernel's duplicate check (`rule_exists`) ignores flags (invert) and an absent Dst, so two Rules that `validateRules` (netcfg.go) accepts as different can collide on add, and `addKernelRule` (rules_linux.go) returns "ErrConflict: the same rule is there already", which is misleading. Either `validateRules` rejects pairs the kernel would treat as the same, or the error names the rule it collided with (looked up in a fresh dump) and says the kernel treats them as one.
- **(b) Repair order.** `reconcileRules` deletes every kernel rule that isn't wanted before it adds the missing ones, so a rule whose action changed (a lookup replaced by a blackhole, same selectors) is gone between the delete and the add. Add the wanted rule first and delete the wrong one after, where the kernel allows it (its `rule_exists` check doesn't compare the action; say what was found in Notes), keeping the undo log correct for both orders.

## Out of scope
- Other TP-135 round-2 findings: they are in TP-135.

## Acceptance
- [ ] (a) a test with a pair Validate allows but the kernel calls one: Validate refuses it, or Apply's error names both rules
- [ ] (b) a lab test of action repair shows the wanted rule present throughout (e.g. a dump between the add and the delete, or the add done before the delete in the request order); mutation: delete-before-add fails it
- [ ] netcfg doc.go says what the duplicate check and the repair order guarantee
- [ ] `make lint`, `make test`, `make lab-gotest PKG=./internal/dataplane/netcfg/...` pass

## Notes
- Source: TP-135 round-1 fixer report (its Log's out-of-scope line).
- Depends on TP-135: the raw rule code (`ruleMsg`, `sendRule`, `delKernelRule`) lives on its branch.

## Log
- 2026-10-29 created in backlog (TP-135 round-1 fixer report)
