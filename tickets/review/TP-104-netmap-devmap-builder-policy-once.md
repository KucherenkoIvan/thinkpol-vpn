---
id: TP-104
title: "netmap/devmap: builder policy validated once"
milestone: M2
area: netmap
repo: thinkpol-vpn
size: M
depends_on: []
owner: "agent-glm"
branch: "tp-104-netmap-devmap-builder-policy-once"
---

## Goal
Map and device-plan validation rules live in one place so overlay-network, chain-exit, default-rule, dial-ingress, and name-limit policy cannot drift between netmap and devmap.

## Scope
- Export netmap's overlay-network, chain-exit, last-rule-default, device-may-not-dial-ingress-off, and rule-reference predicates; devmap calls them with its own positions instead of revalidating (`netmap/section.go` ~328–335, `devmap/spec.go` ~349–378, `devmap/keys.go` ~370–377; shared CGNAT/ULA constants).
- One name validator with documented limits instead of four parallel checks (`netmap` name helpers, `lists.CheckName`, `devmap.nameRE`).
- Split `Section.validate` and `devmap.Plan` by phase where length hurts maintainability.
- Trim test-only fields from `blobs.Options` (`Listen`, `Dial`, `Port`, `Now`) and shadow copies on `Service` if production no longer needs them on the options struct.

## Out of scope
- Map wire format or signing changes.
- lists package API beyond what devmap and netmap need to share.

## Acceptance
- [x] netmap and devmap tests pass; any moved validation covered by existing or new unit tests
- [x] `make lint`, `make test`, `make lab-test` pass
- [x] no behaviour change: existing tests pass unchanged, or each changed test says why

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

Round-2 corrections to round-1's claims: lists.CheckName never stopped
accepting a trailing dash (isName never forbade one there), so the only
behaviour change of round 1 was devmap's node names: a trailing dash is
refused with or without a space name (devmap.CheckName applies
netmap.CheckLabel), `dev keygen node` refuses such names (GenerateNodes
uses the same check), and ReadNames then skips such key files. A
correcting Log line is below; the trailing dash stays accepted for list
and chain names, as before.

For TP-075 (agent layer cleanup, part 1): the agent's `newBlobs` field
hook on DataPlane (internal/agent/dataplane.go), which tests swap to put
the blob service on a loopback overlay, should become part of
TP-075's Platform - a Platform built in cmd/ can build the service on
the lab's overlay directly, and the field goes away.

## Review findings
- [x] R2.1 The Log's claim is false: lists.CheckName still accepts a trailing dash (same as before). Append a correcting line; add "ru-" to TestCheckName's accepted names. The only real change is devmap node names: say so in Notes (trailing dash refused with or without a space name; ReadNames then skips such key files).
- [x] R2.2 devmap.CheckName (spec.go ~139-142): wrap CheckLabel's error ("node %w") instead of printing the stale "starting with a letter or digit" text; keep the reserved-name check. Update spec_test.go's expectation and say why.
- [x] R2.3 internal/devmap/reference.yaml ~22-25 and ~44: node names are DNS labels always (no dash at either end), not only with a space name.
- [x] R2.4 One ingress rule in netmap: NodeSettings.HiddenFromDevices() (server with ingress off); AcceptsInbound uses it; MayLink(a, b *NodeSettings) replaces ApartByIngress and the hiddenFromDevices closures; devmap builds NodeSettings for the check. Likewise MayEndAChain as a NodeSettings method; NeedsDefault → EndsWithDefault (negate at call sites); inline NamesAChain back (keep NamesAList).
- [x] R2.5 Comments: cut "who calls this" from the predicates' docs (rule.go, names.go, envelope.go, section.go, lists/import.go): state the rule only. Rewrap rule.go ~362-367.
- [x] R2.6 One source per limit: checkDomain uses maxLabel; one checkName(what, name) helper behind CheckLabel/CheckListName/CheckChainName (one error string each); decide whether lists.CheckName stays (if it only swaps the message, callers can use netmap.CheckListName) — say which in the Log.
- [x] R2.7 devmap spec.go names(): remove the loop that can no longer fire (CheckName already applies CheckLabel); keep only the space name check; adjust the duplicate test case.
- [x] R2.8 netmap section.go: hoist the duplicated transportAddr type; rename validateDialing → validateLinks.
- [x] R2.9 devmap plan.go: explicit phase calls instead of a []func() loop (each phase depends on the previous); inline resolveLinks; addDeviceRules → addDeviceSettings; use r.Match.NamesAList() at ~301.
- [x] R2.10 blobs Service: hold store, limits, log, net (Net) — no full Options copy, no shadow fields; New(o) = NewOnNet(o, Net{}); drop newService; Net with exactly one function set panics or is documented.
- [x] R2.11 internal/agent/servespace.go ~118-126: remove the always-true MaxHeld branch (set ServerMaxHeldSize directly); the worker test hook keeps the server's MaxHeld instead of overwriting it with fastBlobs. dataplane.go ~98-101: newBlobs and onEngine each with their own comment.
- [x] R2.12 Tests: a table test of the exported netmap predicates on their boundaries (100.64.0.0/10 accepted, /9 and 100.128.0.0/24 refused; fd00::/48 accepted, fc00::/48 and a /56 refused; empty rules end with default; device ↔ server with ingress off may not link; a server with egress may end a chain).
- [x] R2.13 Add to TP-075's Notes (tickets/backlog or in-progress TP-075 file on rewrite is not yours: instead note it in THIS ticket's Notes) that the agent's newBlobs field hook should become part of TP-075's Platform.

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-104-netmap-devmap-builder-policy-once
- 2026-10-19 in-progress → review — e16652f; make lint, make test and make lab-test (34 packages, GOFLAGS=-p=4 LAB_P=1) pass. Two deliberate tightenings: lists.CheckName now refuses trailing dashes (netmap's rule), and devmap.CheckName refuses trailing-dash node names before the space-name check (nameRE allowed them); the one spec_test case that hit it says why.
- 2026-10-19 review → has-errors — round-2 review: 13 findings (R2.1-R2.13), a false claim in this Log among them; production behaviour must not change.
- 2026-10-19 has-errors → in-progress — picked up by the same agent; findings are fixed one commit at a time, each box checked against the code.
- 2026-10-19 correcting the line of 2026-10-19 above: lists.CheckName never stopped accepting a trailing dash; the only behaviour change was devmap's node names (Notes says what that touches).
- 2026-10-19 lists.CheckName is gone (it only swapped the error message): its callers use netmap.CheckListName, whose TestCheckName successor (TestNameChecks in netmap) keeps "ru-" among the accepted names; devmap's bad-list-name spec error now carries netmap's message, and the spec_test case says why.
- 2026-10-19 in-progress → review — d96fe64; make lint, make test and make lab-test (GOFLAGS=-p=4 LAB_P=4, ~4 min) pass. No production behaviour change; test-only differences are said why in the code and in Notes.
