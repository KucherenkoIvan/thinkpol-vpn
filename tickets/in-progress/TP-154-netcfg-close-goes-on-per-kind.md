---
id: TP-154
title: "netcfg (Linux): Close goes on when listing our routes or links fails"
milestone: M2
area: dataplane/netcfg
repo: thinkpol-vpn
size: S
depends_on: [TP-135]
refs: []
owner: "agent-tp-154"
branch: "tp-154-netcfg-close-goes-on-per-kind"
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
- [x] a unit test with a seam for each listing: routes failing still removes rules and restores links; links failing still removes rules and routes; both errors returned. Mutation: returning on either failure again fails it
- [x] `make lint`, `make test`, `make lab-gotest PKG=./internal/dataplane/netcfg/...` pass

## Notes
- Source: TP-135 round-4 fixer (its Log's out-of-scope line).
- 2026-10-29, from TP-135's round-6 correctness check: Close's rule step has the same coupling inside it. `dumpFamilies` (rawrule_linux.go) returns nothing when either family's dump fails, so an IPv6 rule dump that keeps failing stops Close deleting the IPv4 rules too. Each family's dump could fail alone, its error joined, the other family's rules still deleted.

## Review findings
- [ ] R1.1 doc.go and netcfg_linux.go Close comments: say per kind what a failed Close leaves and who can remove it (addresses and links are not removed by the owner's next configurator)
- [ ] R1.2 Log: the dumpFamilies follow-up is filed by the orchestrator

## Log
- 2026-10-29 created in backlog (TP-135 round-4 fixer report)
- 2026-10-31 backlog → in-progress, owner: agent-tp-154
- 2026-10-31 removeOwned: each kind stands alone. Rules first (unchanged), then routes via the closeRoutes seam (a listing failure skips only the route deletes), then links via the closeLinks seam (a failure to build the link ops skips only closeAll); every error joined. removeOwned's comment and doc.go say what each failure skips. Test: TestCloseGoesOnWhenListingRoutesOrLinksFails (routes / links / both), seams FailCloseRouteListing and FailCloseLinkListing
- 2026-10-31 mutations, run in the lab: returning on a route listing failure before the rules step fails the routes and both cases (rules left, links not restored, link error missing); the same for the link listing fails the links and both cases (rules and routes left, route error missing)
- 2026-10-31 make lint, make test, make lab-gotest PKG=./internal/dataplane/netcfg/... pass; full make lab-test passes on 6629ee8
- 2026-10-31 out of scope (not done): the Notes' dumpFamilies coupling. An IPv6 rule dump that keeps failing still stops Close deleting the IPv4 rules. Left for a follow-up because Scope lists routes and links only, and dumpFamilies is shared with Apply's dumpAllRules, where failing fast is right
- 2026-10-31 in-progress → review
- 2026-10-31 review → has-errors (round 1: 1 should-fix docs, 1 follow-up)
- 2026-10-31 has-errors → in-progress, owner: agent-tp-154-fix1
