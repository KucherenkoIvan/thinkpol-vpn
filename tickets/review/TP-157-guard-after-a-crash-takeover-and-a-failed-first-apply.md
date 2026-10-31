---
id: TP-157
title: "Route table: a failed first Apply after a crash takeover leaves the crashed run's guard"
milestone: M2
area: dataplane/routetable
repo: thinkpol-vpn
size: S
depends_on: []
refs: [RR14, RR20]
owner: "agent-tp-157-fix1"
branch: "tp-157-guard-after-a-crash-takeover-and-a-failed-first-apply"
---

## Goal
After a crash takeover, the IPv6 guard is never wider than the new rules, even when the first Apply fails.

Outcome (review round 1): the scenario is already closed by the failed start's undo, which removes the crashed run's guard and routes (Notes). The branch delivers tests that pin that, docs that say it, and the TP-148 leftovers; the start-up guard it first added is reverted.

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
- [x] ~~a unit test: a failed first Apply after a crash leaves a guard no wider than the new Want~~ superseded in round 1 (R1.2): a unit test that a failed first Enforce applies no guard and its Close removes the crashed run's guard and routes, and an agent test that a start failing at the route table's first Enforce closes the route table; each mutation-checked
- [x] routetable doc.go's "no guard until" paragraph says what happens at startup after a crash (RR14 unchanged; RR20 names the crashed run's guard)
- [x] `make lint`, `make test` pass

## Notes
- Source: TP-127 round-1 correctness review (pre-existing, logged out of scope there).
- Round 1 (R1.2, decided): the scenario isn't reachable through the agent. A first `Enforce` that fails fails `grow`, so `engine.Apply` fails (internal/dataplane/routetable.go `grow`) and `runner.start` runs its undo (internal/agent/dataplane.go, after `engine.Apply`): `engine.Close` closes the route table, and `Enforcer.Close` closes the guard, then the configurator. Both firewall guards' Close remove the guard by name whether or not they applied it (Linux: `removeGuard` deletes the table; macOS: `flush` of the anchor and release of the crashed run's reference from its record), and the configurator's Close removes every route and rule with the owner's protocol. So the crashed guard lasts until the same start's undo, milliseconds, and RR20 applies while the start is retried. `Enforce` is used only through that path (cmd/thinkpol/platform.go → the engine), so no Enforcer outlives a failed first Enforce.
- The start-up guard the first round added (`guardFor(nil, w)`: endpoints, upstreams and mark) is reverted: it bought nothing at the agent level, and each failed start retry (every 5 s) would put it in and take it out again, resetting the device's live direct IPv6 flows (Linux's tcp-reset rule; macOS's state kill after an anchor load). `apply` again skips the guard until routes went in, `guardFor` takes `held, want Want` again, and `reapplyGuard` returns while nothing went in.
- What the branch does instead: `TestAFailedFirstEnforcesCloseRemovesACrashedRunsGuard` (routetable) and the "first enforce" case of `TestAFailedStartUndoesWhatItOpened` (agent) pin the real protection; doc.go and the Enforcer's comments say it; RR20 names the crashed run's guard; and the TP-148 leftovers (Also list) stay.

## Log
- 2026-10-29 created in backlog (TP-127 round-1 review)
- 2026-10-31 backlog → in-progress, owner: agent-tp-157
- 2026-10-31 `guardFor(held *Want, want)`: a nil held (no Want's routes in yet) is taken as want with nothing direct, so `apply` and `reapplyGuard` always apply a guard once a Want is given; a takeover's failing first Apply replaces the crashed run's guard with the new Want's endpoints, upstreams and mark (Notes: option picked and why). Tests: `TestAFailedFirstApplyReplacesACrashedRunsGuard` (fake guard seeded with a crashed guard, failing configurator, narrower Want) and `TestTheGuardBeforeAnyRoutesWentIn` (guardFor with nil held). Mutations run: `if held != nil` skipping the guard in apply again fails the first (exempts 2001:db8:d1::/48, GuardEnforced false); dropping `h.Direct = nil` (nil held → want's full guard) fails both.
- 2026-10-31 docs: doc.go's "until a Want's routes first go in" paragraph and "Ownership and crashes" say what happens at a start; RR14 (When, What leaks, Ticket) and routing.md's guard bullet likewise. Also list done: the fix-while-failing slack widened to 1 s, the not-failing bound loosened to 2.5 s, and doc.go/RR19/RR22 retry timing made exact (RetryAfter after the attempt ends, or a debounce after the event if later: up to about 5.2 s). routing.md's "up to 5 s while the routes fail" (two bullets) left as is: a summary pointing at RR19/RR22.
- 2026-10-31 make lint, make test green on the Mac; the first fix commit went in before make lint (an errcheck on `defer e.Close()`, fixed in the next commit).
- 2026-10-31 make lab-test (full, LAB_P=1) green on 13c53bb: 36 packages, routetable's lab tests included. Not verified: a real crash takeover on a device (the macOS pf anchor replaced by a failing first Apply), and the startup guard with an unsupported kernel; both by reasoning and the fakes only.
- 2026-10-31 in-progress → review
- 2026-10-31 review → has-errors (round 1: 3 should-fix + 1 doc from TP-153)
- 2026-10-31 has-errors → in-progress, owner: agent-tp-157-fix1
- 2026-10-31 round 1 fix (R1.2): the start-up guard in `apply` reverted (`guardFor(held, want Want)`, `apply` and `reapplyGuard` skip the guard until routes went in), with a comment saying why; `TestAFailedFirstApplyReplacesACrashedRunsGuard` and `TestTheGuardBeforeAnyRoutesWentIn` removed with it. New: `TestAFailedFirstEnforcesCloseRemovesACrashedRunsGuard` (fake guard seeded with a crashed guard, failing configurator: no guard applied, GuardEnforced false, Close closes guard and configurator) and the "first enforce" case of agent `TestAFailedStartUndoesWhatItOpened` (route table's first Enforce fails: StepRouteTable, the table, TUN and configurator closed once). Mutations run: Close skipping `guard.Close` when nothing was applied fails the first (guard removed false); the start-up guard put back in `apply` fails it too (one guard applied, GuardEnforced true); `runner.start` skipping the undo at StepRouteTable fails the agent case (TUN, configurator, route table closed 0 times). All restored.
- 2026-10-31 docs (R1.1, R1.3, R1.4): RR14 back to its pre-TP-157 text; RR20 says a failed start's undo removes a crashed run's routes and guard too; routing.md's start-up sentence removed and its two "up to 5 s while the routes fail" made "about 5 s, more while retries keep failing"; doc.go's "until a Want's routes first go in" and "after a crash" paragraphs say the failed start's Close removes the crashed guard; doc.go and the Enforcer's comment say a rule added with our protocol brings a re-apply (TP-153); the Enforce comment says no guard before the first routes. Merged origin/rewrite first (f511b2c).
- 2026-10-31 not done (round-1 nits): no test of a failing first Enforce followed by a good one ending in `GuardFor(w)` (true by construction, as before TP-157); the retry-timing wording doesn't count a slow guard Apply (pfctl timeout) in "the Apply".
- 2026-10-31 make lint, make test green on the Mac; make lab-test (full, LAB_P=4) green on f9c166e: 36 packages. Not verified on a device: a crash takeover whose first start fails (the pf anchor and the nftables table removed by the undo); by the firewall unit and lab tests of a fresh guard's Close and by reasoning.
- 2026-10-31 in-progress → review
