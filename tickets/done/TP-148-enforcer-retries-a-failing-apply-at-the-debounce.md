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
- Picked rate-limiting, not ignoring: an event while failing may be the fix (the TUN coming up), so it is held, not dropped. `apply` records when the attempt ended (`lastAttempt`, in the same locked section as `failing`). While `failing`, the watcher's timer is what is left of `RetryAfter` since then (`retryIn`). A settled route event goes back to that timer, and so does the check after a failed Enforce. A guard-only failure (`guardFailing`) still re-applies on events at the debounce, and the guard's own Watch (`gch`) is untouched.
- TestEnforcerAppliesChangesAndReappliesOnEvents takes about 6 s, as it did on rewrite before this change (its one failed re-Apply was already retried by the backstop RetryAfter later); this change doesn't lengthen it. It removes a race there: the check after the failed Enforce could re-apply after `setFail(false)` and make the next Enforce a no-op.

## Review findings
Round 1 (2026-10-31: go-paranoid, pocket-torvalds, go-style; 5 should-fix).
- [x] R1.1 (paranoid #1): RESIDUAL-RISKS.md RR22 and RR19 don't say that, while the routes fail, events (a hostile on-link route, a TUN drop) are held up to RetryAfter (5 s) before the re-apply, where they used to be taken at the 200 ms debounce. Make both rows accurate and consistent; check the PRD requirement their Breaks column names.
- [x] R1.2 (paranoid #2): the hold on the watcher's check after a failed Enforce (routetable.go:701) is untested; dropping `if e.retryIn() == 0` passes every test.
- [x] R1.3 (paranoid #3): that events on the other paths (`gch`, regwatch/rewatch) don't push the retry deadline back (`backstop`, routetable.go:810-811) is untested; reverting `backstop` to `wait = RetryAfter` passes every test.
- [x] R1.4 (pocket-torvalds S1): doc.go:232-233 promises a fix-carrying event while failing is taken within RetryAfter; no test bounds it (a `RetryAfter + retryInLocked()` mutation passes).
- [x] R1.5 (pocket-torvalds S2): the open point is wrong: TestEnforcerAppliesChangesAndReappliesOnEvents already took about 5 s for its retry step on rewrite; correct Notes/Log.
- [x] Nit: rewrap the Enforcer comment at routetable.go:271.

## Log
- 2026-10-29 created in backlog (TP-135 round-2 review, S2)
- 2026-10-31 backlog → in-progress, owner: agent-tp-148
- 2026-10-31 done: while the routes fail, Watch events and the post-Enforce check wait until `RetryAfter` after the last attempt (`retryIn`, `backstop`, `watch` in routetable.go); Enforcer doc comment and routetable/doc.go say so. New test TestAFailingApplyIsRetriedAtRetryAfterNotOnEachEvent (fake Apply records attempt times; events pumped every 20 ms while failing). Mutations run: dropping the hold on events fails it (attempts 204 ms apart, 34 attempts); holding events even when not failing fails it (no re-Apply on an event).
- 2026-10-31 `make lint`, `make test` green; `make lab-test` green on dc304af (36 packages). Not verified: on a real kernel, that the undo's RTM_DELRULE events are the ones the hold absorbs (that loop was not reproduced in the lab).
- 2026-10-31 out of scope: while only the guard fails, a `gch`/`regwatch` event still restarts the `RetryAfter` backstop timer (pre-existing). While the routes fail, the deadline is now measured from the last attempt, so events no longer push it back.
- 2026-10-31 in-progress → review
- 2026-10-31 review → has-errors (round 1: 5 should-fix)
- 2026-10-31 has-errors → in-progress, owner: agent-tp-148-fix1
- 2026-10-31 R1.1: RR19 and RR22 say that while the routes fail an event (a TUN drop, a foreign on-link route) is held for the next retry, up to RetryAfter (5 s) after the failed attempt, where it was taken a debounce later; RR19 no longer says a burst restarts the debounce (a fixed window). Breaks unchanged (D4, R2; R2): PRD D4 and R2 cite no rows in their text, so no PRD change. docs/design/routing.md's two lines citing RR19 and RR22 say "up to 5 s while the routes fail".
- 2026-10-31 R1.2–R1.4 tests, mutation-checked: TestTheCheckAfterAFailedEnforceWaitsForRetryAfter (dropping `if e.retryIn() == 0` on the check fails it: retried 202 ms later); TestGuardEventsDontPushTheRoutesRetryBack, guard events every 300 ms while the routes fail (`backstop` back to `wait = RetryAfter` fails it: no retry within 10 s); TestAFixWhileFailingIsTakenWithinRetryAfter, a single fix-carrying event (`wait = RetryAfter + e.retryInLocked()` fails it: not taken within 10 s). The `regwatch`/`rewatch` paths go through the same `backstop` but have no test of their own. RetryAfter is a const with no test seam, so the new tests are t.Parallel and take about 5 s each in real time.
- 2026-10-31 R1.5: the open point was wrong: with rewrite's routetable.go, TestEnforcerAppliesChangesAndReappliesOnEvents took 6.03 s, the same as on this branch (run here); Notes corrected.
- 2026-10-31 nits: Enforcer comment rewrapped; `attempted` → `lastAttempt`; `settle`'s comment says it's a fixed window; checkRepairs' comment; the not-failing bound is now 1 s (not RetryAfter/2); the retry test polls for a second failed attempt, then waits 1 s, instead of sleeping RetryAfter+2 s; its doc no longer claims the after-recovery check. Re-ran its two old mutations: dropping the hold on events fails it (207 ms gaps); holding events always fails it (no re-Apply on an event).
- 2026-10-31 not done (suspicions, left as they are): P2 `lastAttempt` is stamped before the guard's Apply (the field comment says "of the routes"); P3 a guard-only failure could loop on `gch` if a rolled-back guard transaction emits events (out of scope per the ticket).
- 2026-10-31 `make lint`, `make test` green; `make lab-test` green on 23eeb9b (exit 0, 36 packages in the lab node, routetable among them). Not verified: on a real kernel, that the undo's RTM_DELRULE events are the ones the hold absorbs.
- 2026-10-31 in-progress → review
- 2026-10-31 review → done, merged into rewrite (round 1: 5 should-fix fixed; final check: merge; nits left for TP-157: TestAFixWhileFailingIsTakenWithinRetryAfter allows only 500 ms past RetryAfter and the not-failing bound in the retry test is 1 s, both tight under load; doc.go:232-233 and RR19/RR22 understate the hold by the rest of a failing Apply and one settle)
