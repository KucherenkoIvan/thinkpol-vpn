---
id: TP-157
title: "Route table: a failed first Apply after a crash takeover leaves the crashed run's guard"
milestone: M2
area: dataplane/routetable
repo: thinkpol-vpn
size: S
depends_on: []
refs: [RR14]
owner: ""
branch: ""
---

## Goal
After a crash takeover, the IPv6 guard is never wider than the new rules, even when the first Apply fails.

## Scope
- `apply` (internal/dataplane/routetable/routetable.go) applies the guard only when `held` (`e.applied`) is set, so a first Apply that fails applies none (routetable doc.go: "Until a Want's routes first go in, no guard is applied"). After a crash, the guard's table (Linux) or anchor (macOS) and the crashed run's routes are still in place, so the crashed run's guard keeps exempting what the old rules routed direct, possibly more than the new Want does, until an Apply succeeds.
- Options, pick one and say why in Notes:
  - after a takeover, treat the crashed run's routes (what Survey finds of ours) as `held`, so `guardFor(held, w)` narrows the guard to what both exempt;
  - read the crashed guard's Exempt back and intersect it with `GuardFor(w)`;
  - anything else that never widens and never refuses IPv6 to the links' endpoints (the reason doc.go gives for no guard).
- Keep `guardFor` the one place that picks the guard (TP-127's decision).

## Out of scope
- The retry interval while failing: TP-148.

## Acceptance
- [ ] a unit test with the fake configurator and guard: a guard and routes left by a crash, then a first Apply with a narrower Want that fails; the guard after it exempts nothing the new Want doesn't. Mutation: `held == nil` skipping the guard again fails it
- [ ] routetable doc.go's "no guard until" paragraph and RR14 say what happens at startup
- [ ] `make lint`, `make test` pass

## Notes
- Source: TP-127 round-1 correctness review (pre-existing, logged out of scope there).

## Log
- 2026-10-29 created in backlog (TP-127 round-1 review)
