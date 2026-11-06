---
id: TP-156
title: "netcfg (macOS): a valid supervisor.routes is trusted, though no darwin supervisor exists"
milestone: M2
area: dataplane/netcfg
repo: thinkpol-vpn
size: S
depends_on: []
refs: [RR53]
owner: ""
branch: ""
---

## Goal
Decide whether a Mac should treat a `supervisor.routes` record as thinkpol's at all, and make the code and docs agree with the answer.

## Scope
- `Owners` (internal/dataplane/netcfg/netcfg.go) includes `OwnerSupervisor` on every OS. On darwin, `thinkpolRoutes` (netcfg_darwin.go) and `readRecords` (inspect_darwin.go) read every owner's record, so the routes a valid `supervisor.routes` names count as thinkpol's: no other owner touches them, Survey doesn't count them as foreign, and diag lists them as the supervisor's. No darwin supervisor exists, so only a person (or other software) can have written that record.
- Options, pick one and say why in Notes:
  - skip `OwnerSupervisor` on darwin (a per-OS owner list): its routes become foreign, and a corrupt one is no longer reported;
  - keep it, and say in netcfg doc.go and RR53 why trusting it is acceptable.
- TP-124 chose to keep the owner for the corrupt case (netcfg doc.go: "skipping the owner instead would also change what a valid one means"); this ticket decides the valid case.

## Out of scope
- Linux: the supervisor runs there.

## Acceptance
- [ ] the decision is in Notes and netcfg doc.go (and RR53 if it changes what is reported)
- [ ] if skipped: a darwin test where a valid `supervisor.routes` names a route, and Survey counts it as foreign and Inspect doesn't list it as the supervisor's; mutation: the full owner list fails it
- [ ] `make lint`, `make test` pass

## Notes
- Source: TP-124 round-2 review (R2.6) and its Log's out-of-scope line ("on darwin a valid `supervisor.routes` … is still trusted as thinkpol's").

## Log
- 2026-10-29 created in backlog (TP-124 round-2 review)
