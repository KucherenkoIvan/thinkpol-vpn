---
id: TP-154
title: "netcfg (Linux): Close goes on when listing our routes or links fails"
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
Close removes what it can of each kind (rules, routes, addresses and links) even when listing one kind fails, as TP-135 made it do for rules.

## Scope
- `removeOwned` (internal/dataplane/netcfg/netcfg_linux.go, TP-135's branch) returns at once when `ownKernelRoutes` or `newNetlinkOps` fails, before it removes any rule, route or address, leaving everything to the owner's next configurator. A clean Close can then leave the route table's rules and unreachable defaults behind.
- Make each kind independent: a failure to list routes skips the route deletes only; a failure to build the link ops skips `links.closeAll` only. Rules still go before the routes they lead to. Every error is joined into Close's result.
- `removeOwned`'s comment and netcfg doc.go say what Close does on each kind of failure.

## Out of scope
- Rule dumps during Close: done in TP-135 (`removeOwnRules`).

## Acceptance
- [ ] a unit test with a seam for each listing: routes failing still removes rules and restores links; links failing still removes rules and routes; both errors returned. Mutation: returning on either failure again fails it
- [ ] `make lint`, `make test`, `make lab-gotest PKG=./internal/dataplane/netcfg/...` pass

## Notes
- Source: TP-135 round-4 fixer (its Log's out-of-scope line).

## Log
- 2026-10-29 created in backlog (TP-135 round-4 fixer report)
