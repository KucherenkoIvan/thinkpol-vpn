---
id: TP-151
title: "macOS guard diagnostics: show what the anchors before the hook hold"
milestone: M2
area: dataplane/firewall
repo: thinkpol-vpn
size: M
depends_on: [TP-129]
refs: [RR12]
owner: ""
branch: ""
---

## Goal
`thinkpol diag` on a Mac shows why the guard says `ipv6_guard_not_enforced` when the reason is a pass inside an anchor evaluated before the hook, instead of a guard check that reads "hooked".

## Scope
- Today `inspectGuardCheck` (internal/dataplane/firewall/inspect_darwin.go, TP-129's branch) sets `PFReport.GuardCheck` from `hooked()`, which reads only the main ruleset. TP-129's `checkBypass` walks the anchors called above the hook (`anchorWalk`) and finds passes there, so the guard is not enforced while the snapshot says "hooked", with only the anchor lines in `MainRules` as evidence.
- Report the walk's findings: each `bypass` (`why`, and `rule` with where pf holds it), or the walk's read error. Add a field to `routetable.PFReport` and to `DiagPfGuardCheck` in proto/thinkpol/localapi/v1/localapi.proto (`make proto`), map it in internal/agent/localapi/diagnose.go, and render it in `thinkpol diag`.
- Decide whether `GuardCheck` keeps `hooked()`'s verdict (the main ruleset alone) or says "bypassed" when the walk finds one; the field's comment and the proto comment say which.
- Inspect must not cost more than the guard's own check: the same walk, the same 16-anchor bound.

## Out of scope
- `nat pass` / `binat pass` / `rdr pass`: TP-152.

## Acceptance
- [ ] a fake-pfctl test: a quick pass in an anchor called above the hook shows in the snapshot as a finding with its anchor and rule; mutation: dropping the findings fails it
- [ ] an unreadable or over-bound walk shows as such in the snapshot
- [ ] the localapi mapping has a test; the proto field has a comment
- [ ] `make lint`, `make test` pass

## Notes
- Source: TP-129 implementer's Log ("not covered: InspectIPv6Guard's snapshot doesn't show what the anchors above the hook hold").
- Depends on TP-129: `anchorWalk`, `bypass` and `checkBypass`'s findings live on its branch.

## Log
- 2026-10-29 created in backlog (TP-129 implementer report)
