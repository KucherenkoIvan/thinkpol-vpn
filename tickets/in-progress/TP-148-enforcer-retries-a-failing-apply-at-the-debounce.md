---
id: TP-148
title: "Route table: a failing Apply is retried at the debounce, not RetryAfter"
milestone: M2
area: dataplane/routetable
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-148-fix1"
branch: "tp-148-enforcer-retries-a-failing-apply-at-the-debounce"
---

## Goal
While Apply keeps failing, the route-table Enforcer retries every `RetryAfter` (5 s), as its doc says, instead of every `debounce` (200 ms) for as long as the failure lasts.

## Scope
- The loop: a failing Apply's undo deletes the rules it had added; the Linux Watch counts a deleted rule of ours as relevant (`relevant`, RTM_DELRULE, netcfg/watch_linux.go); `watch` (internal/dataplane/routetable/routetable.go) gets the event, `settle` waits out the 200 ms `debounce`, and `reapply` runs `apply`, which fails and undoes again. `backstop` only uses `RetryAfter` for the timer, not for Watch events.
- Fix direction: while `e.failing`, ignore Watch events or hold them until `RetryAfter` has passed since the last attempt. Rate-limiting is the safer one: an event while failing may be the fix (the TUN coming up), and it then waits at most `RetryAfter`. Say which was picked and why in Notes.
- The guard's own Watch (`gch`, `reapplyGuard`) is not in the loop; leave it.

## Out of scope
- Why Apply fails: TP-149 (a kernel without IPv6), TP-135 R2.2 (a /0 rule destination).

## Acceptance
- [x] a unit test with the fake configurator: Apply fails persistently and Watch fires after each attempt; re-applies come at `RetryAfter`, not `debounce` (the test's clock or a count over a window); mutation: the old behaviour fails it
- [x] a Watch event while not failing still re-applies after `debounce`
- [x] the Enforcer's doc comment and routetable/doc.go say what happens to events while failing
- [x] `make lint`, `make test` pass

## Notes
- Source: TP-135 round-2 correctness review, suspicion S2.
- Picked rate-limiting, not ignoring: an event while failing may be the fix (the TUN coming up), so it is held, not dropped. `apply` records when the attempt ended (`attempted`, in the same locked section as `failing`). While `failing`, the watcher's timer is what is left of `RetryAfter` since then (`retryIn`). A settled route event goes back to that timer, and so does the check after a failed Enforce. A guard-only failure (`guardFailing`) still re-applies on events at the debounce, and the guard's own Watch (`gch`) is untouched.

## Review findings
Round 1 (2026-10-31: go-paranoid, pocket-torvalds, go-style; 5 should-fix).
- [ ] R1.1 (paranoid #1): RESIDUAL-RISKS.md RR22 and RR19 don't say that, while the routes fail, events (a hostile on-link route, a TUN drop) are held up to RetryAfter (5 s) before the re-apply, where they used to be taken at the 200 ms debounce. Make both rows accurate and consistent; check the PRD requirement their Breaks column names.
- [ ] R1.2 (paranoid #2): the hold on the watcher's check after a failed Enforce (routetable.go:701) is untested; dropping `if e.retryIn() == 0` passes every test.
- [ ] R1.3 (paranoid #3): that events on the other paths (`gch`, regwatch/rewatch) don't push the retry deadline back (`backstop`, routetable.go:810-811) is untested; reverting `backstop` to `wait = RetryAfter` passes every test.
- [ ] R1.4 (pocket-torvalds S1): doc.go:232-233 promises a fix-carrying event while failing is taken within RetryAfter; no test bounds it (a `RetryAfter + retryInLocked()` mutation passes).
- [ ] R1.5 (pocket-torvalds S2): the open point is wrong: TestEnforcerAppliesChangesAndReappliesOnEvents already took about 5 s for its retry step on rewrite; correct Notes/Log.
- Nit: rewrap the Enforcer comment at routetable.go:271.

## Log
- 2026-10-29 created in backlog (TP-135 round-2 review, S2)
- 2026-10-31 backlog → in-progress, owner: agent-tp-148
- 2026-10-31 done: while the routes fail, Watch events and the post-Enforce check wait until `RetryAfter` after the last attempt (`retryIn`, `backstop`, `watch` in routetable.go); Enforcer doc comment and routetable/doc.go say so. New test TestAFailingApplyIsRetriedAtRetryAfterNotOnEachEvent (fake Apply records attempt times; events pumped every 20 ms while failing). Mutations run: dropping the hold on events fails it (attempts 204 ms apart, 34 attempts); holding events even when not failing fails it (no re-Apply on an event).
- 2026-10-31 `make lint`, `make test` green; `make lab-test` green on dc304af (36 packages). Not verified: on a real kernel, that the undo's RTM_DELRULE events are the ones the hold absorbs (that loop was not reproduced in the lab).
- 2026-10-31 out of scope: while only the guard fails, a `gch`/`regwatch` event still restarts the `RetryAfter` backstop timer (pre-existing). While the routes fail, the deadline is now measured from the last attempt, so events no longer push it back.
- 2026-10-31 in-progress → review
- 2026-10-31 review → has-errors (round 1: 5 should-fix)
- 2026-10-31 has-errors → in-progress, owner: agent-tp-148-fix1
