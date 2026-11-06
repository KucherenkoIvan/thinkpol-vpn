---
id: TP-193
title: "dns: an owed read stays stale when resolv.conf is re-linked to a target that appears later"
milestone: later
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: [TP-130]
refs: []
owner: ""
branch: ""
---

## Goal
While a read owed after a failed change is pending, re-linking /etc/resolv.conf to a dangling target that later appears ends the stale state once the target can be read.

## Scope
Since TP-130, `linkedOriginal` (`internal/dataplane/dns/resolvconf.go`) re-reads a dangling link's target only while the first read is owed; an owed read after a failed change never re-reads it, so `Problem()` reports stale until another program rewrites resolv.conf. Reported, not silent. Before TP-130 the same re-link was already broken, silently.

## Out of scope
None named.

## Acceptance
- [ ] a unit test: owed read pending, resolv.conf re-linked to a missing target, the target appears with servers: they are told and `Problem()` is nil
- [ ] `make lint`, `make test` pass

## Notes
- Found in TP-130's delta check, 2026-11-07.
- Also there: the new test `TestResolvConfAnOwedReadThatNamesNoServerKeepsTheUpstreams` doesn't assert the `-dns-upstream` hint is absent right after the failed change (a mutation dropping `&& !r.owed` from the warn condition survives); add that assertion here.

## Log
- 2026-11-07 created in backlog
