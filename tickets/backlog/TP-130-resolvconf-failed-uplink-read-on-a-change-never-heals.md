---
id: TP-130
title: "dns: a failed uplink read on the tick resolv.conf changes is never retried"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: [TP-128]
refs: []
owner: ""
branch: ""
---

## Goal
On the resolv.conf path, a read of resolved's uplink file that fails on the tick where resolv.conf changes is retried until it works. The node tells the new upstreams, or reports them stale, instead of keeping the old ones silently.

## Scope
- Today (`resolvconf.go`, `apply`, ~395-410), on a tick where the content changed, `ok=false` still records the new content as the original and tells nothing. Two cases end up there:
  - resolved's uplink file is missing;
  - with TP-128, the uplink file is empty.
- On later ticks `changed` is false, and the first read is no longer owed, so a good uplink read is never told.
- Result: direct names keep going to the previous upstreams until resolv.conf changes again, and `Problem()` returns nil.
- Scenario: upstreams known (`192.0.2.53`). A DHCP client atomically rewrites resolv.conf to `nameserver 127.0.0.53` while the uplink file is missing.
- This predates TP-128. Found by its round-1 correctness review.
- Fix: keep "a read is owed" after a failed read on a change, so the next good read is told, and report `ErrUpstreamsStale` meanwhile. Extend `TestARewrittenResolvConfFiltersStubUpstreams` with the recovery step.

## Acceptance
- [ ] a test of the scenario: the failed tick reports stale, and the next tick with a good uplink tells the new upstreams. Mutation: dropping the owed read fails it
- [ ] `make lint`, `make test` pass

## Log
- 2026-10-22 created in backlog (TP-128 review round 1)
