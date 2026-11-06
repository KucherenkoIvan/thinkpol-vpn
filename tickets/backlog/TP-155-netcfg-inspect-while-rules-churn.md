---
id: TP-155
title: "netcfg (Linux): diagnostics while the rules keep changing"
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
`thinkpol diag` says something useful about the rules while someone keeps changing them, instead of an internal error.

## Scope
- `Inspect` reads rules through `ownedRules` → `dumpAllRules` → `dumpRules` (internal/dataplane/netcfg/inspect_linux.go and rawrule_linux.go, TP-135's branch). Under steady churn `dumpUntilAgreed` never sees two dumps agree and fails with `errDumpsDisagree`, so `RulesUnreadable` carries that error and diag shows no rules.
- Pick one, and say why in Notes:
  - report `errDumpsDisagree` as plain words ("the rules kept changing while they were read; try again"), or
  - show the last dump's rules, marked unverified (a field on `Inspection`, through the localapi proto and diag's rendering).
- Diagnostics only: Apply, Survey and Close keep their current handling of churn.

## Out of scope
- Apply's and Survey's failure under churn: decided in TP-135 (R4.3).

## Acceptance
- [ ] a test with an injectable dump that never agrees: Inspect's result says the rules were changing (and, if chosen, holds the last dump marked unverified); mutation: passing the raw error through fails it
- [ ] netcfg doc.go's churn paragraph covers Inspect
- [ ] `make lint`, `make test`, `make lab-gotest PKG=./internal/dataplane/netcfg/...` pass

## Notes
- Source: TP-135 round-4 fixer (its Log's out-of-scope line).

## Log
- 2026-10-29 created in backlog (TP-135 round-4 fixer report)
