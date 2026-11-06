---
id: TP-163
title: "netcfg Close: a failing IPv6 rule dump stops the IPv4 rule deletes"
milestone: M2
area: dataplane/netcfg
repo: thinkpol-vpn
size: S
depends_on: [TP-154]
refs: []
owner: ""
branch: ""
---

## Goal
During Close, a rule dump that keeps failing for one family doesn't stop the other family's rules from being removed.

## Scope
- `removeOwned` (internal/dataplane/netcfg/netcfg_linux.go:570-571) passes `removeOwnRules` a `dumpOwn` that calls `dumpFamilies(c.rules, c.closeDump)`. `dumpFamilies` (rawrule_linux.go:73-84) dumps IPv4, then IPv6, and returns nothing at the first family that fails. So an IPv6 dump that fails on every attempt makes each of `removeOwnRules`' dumps fail, no IPv4 rule is deleted, and the IPv4 mark-invert rules stay after Close.
- Apply also goes through `dumpFamilies` (via `dumpAllRules`, rawrule_linux.go:68-70), and stopping there is right: Apply needs both families' rules to compare against. Leave Apply as it is.
- Give Close a path that dumps and removes each family separately: one family's failing dump is reported (joined with the rest, as `removeOwned` does now) and the other family's rules still go.
- netcfg doc.go and `removeOwned`'s comment say per family what a failed Close leaves.

## Out of scope
- Apply's dump behaviour.
- Routes and links during Close: TP-154.

## Acceptance
- [ ] a unit test with a fake dump: the IPv6 dump fails on every call, and Close still deletes every IPv4 rule of ours and returns the IPv6 error. Mutation: going back to `dumpFamilies` for Close fails it
- [ ] Apply still stops at the first family whose dump fails (an existing or new test pins it)
- [ ] doc.go and `removeOwned`'s comment match
- [ ] `make lint`, `make test` pass; `make lab-gotest PKG=./internal/dataplane/netcfg/...` passes

## Notes
- Source: TP-154's out-of-scope note (tickets/done/TP-154-netcfg-close-goes-on-per-kind.md): TP-154 made Close go on per kind (rules, routes, links) but left the rule dump's per-family stop alone.

## Log
- 2026-10-31 created in backlog (TP-154 out-of-scope note)
