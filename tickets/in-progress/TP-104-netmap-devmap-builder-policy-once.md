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
- [ ] netmap and devmap tests pass; any moved validation covered by existing or new unit tests
- [ ] `make lint`, `make test`, `make lab-test` pass
- [ ] no behaviour change: existing tests pass unchanged, or each changed test says why

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-104-netmap-devmap-builder-policy-once
