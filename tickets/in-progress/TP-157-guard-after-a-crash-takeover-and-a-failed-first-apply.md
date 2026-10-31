---
id: TP-157
title: "Route table: a failed first Apply after a crash takeover leaves the crashed run's guard"
milestone: M2
area: dataplane/routetable
repo: thinkpol-vpn
size: S
depends_on: []
refs: [RR14]
owner: "agent-tp-157"
branch: "tp-157-guard-after-a-crash-takeover-and-a-failed-first-apply"
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
- Also (leftovers from TP-148's final check, same package):
  - routetable_test.go `TestAFixWhileFailingIsTakenWithinRetryAfter`: widen the slack past RetryAfter from 500 ms to 1 s, like `TestGuardEventsDontPushTheRoutesRetryBack`.
  - routetable_test.go `TestAFailingApplyIsRetriedAtRetryAfterNotOnEachEvent`: loosen the not-failing bound from 1 s back to 2.5 s, still well apart from the 200 ms debounce and the 5 s RetryAfter.
  - doc.go's "taken at most RetryAfter later" and RR19/RR22's "up to 5 s after the failed attempt": make them exact (an event during a failing Apply waits RetryAfter after that Apply ends; one near the retry is taken a debounce after it, up to about 5.2 s after the attempt).

## Out of scope
- The retry interval while failing: TP-148.

## Acceptance
- [ ] a unit test with the fake configurator and guard: a guard and routes left by a crash, then a first Apply with a narrower Want that fails; the guard after it exempts nothing the new Want doesn't. Mutation: `held == nil` skipping the guard again fails it
- [ ] routetable doc.go's "no guard until" paragraph and RR14 say what happens at startup
- [ ] `make lint`, `make test` pass

## Notes
- Source: TP-127 round-1 correctness review (pre-existing, logged out of scope there).
- Option picked: neither of the first two, a third. With no Want's routes in yet, `guardFor` takes the routes in place as the new Want with nothing direct, so the guard is the Want's endpoints, upstreams and mark alone. Why: Survey reports only foreign routes, and the Guard port can't read a guard back, so options 1 and 2 would each need a new netcfg or firewall-adapter read (per OS) for a narrower result. This one never widens past the new Want, keeps the links reachable (endpoints exempt by address on macOS), and stays inside `guardFor` (its `held` is now `*Want`; nil is "none of ours in yet"). Cost: the device's own IPv6 to direct destinations is refused until the first Apply works.
- Behaviour change beyond the crash case: a fresh start whose first Apply fails (no crash) now applies that endpoints-only guard where it applied none, so the device's own IPv6 is refused but for endpoints, upstreams and link-scoped until the routes go in. Stricter, never wider; that includes a kernel without rule protocols (ErrorUnsupported), where the guard (nftables) may still go in.

## Log
- 2026-10-29 created in backlog (TP-127 round-1 review)
- 2026-10-31 backlog → in-progress, owner: agent-tp-157
