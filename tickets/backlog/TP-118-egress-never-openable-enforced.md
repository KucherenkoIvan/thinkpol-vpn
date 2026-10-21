---
id: TP-118
title: "Egress: keep the metadata services out of EgressAllowed"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-112]
refs: [DESIGN#dns]
owner: ""
branch: ""
---

## Goal
The addresses the DNS refusal hint never suggests opening (the cloud metadata services and the never-routable ranges, `supervisor.EgressNotWorthAllowing`) are not merely unsuggested but refused even when `Options.EgressAllowed` names them: a mistaken `-egress-allowed 169.254.0.0/16` cannot open a space's way to a metadata service.

## Scope
- Enforce what TP-112's R2.1 deliberately left as a naming-only check: a destination `EgressNotWorthAllowing` names is dropped by the egress path and closed by the worker's rules even when `EgressAllowed` names it (config may still accept the prefix, so a probe can say it was dropped, not that the flag was bad — decide which).
- `EgressRefused` currently honours `allowed` first; the root's accept rules jump ahead of the drops. Both need the closed set to win there.
- Say in DESIGN.md ("Upstreams" and wherever `EgressAllowed` is described) that a closed range is refused whatever it names.

## Out of scope
- Any change to which addresses are closed (that list is TP-112's, reviewed twice).

## Acceptance
- [ ] a test that `EgressAllowed` naming `168.63.129.16` (and a link-local metadata range) still leaves the destination refused by `EgressRefused` and dropped in the lab
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Filed from TP-112's round-2 review (R2.1): `EgressMustStayClosed` was documented as a block nothing enforced, so it was renamed to `EgressNotWorthAllowing` — the enforcement is this ticket's decision.

## Log
- 2026-10-21 created in backlog (TP-112 review round 2, R2.1)
