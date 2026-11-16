---
id: TP-221
title: "Flaky TestIdleStreamsDontStarveRouting under load"
milestone: M2
area: agent/supervisor
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-201]
refs: []
owner: "agent-tp-221"
branch: "tp-221-flaky-idle-streams-test"
---

## Goal
`TestIdleStreamsDontStarveRouting` (internal/agent/supervisor/shared_test.go, from TP-201) passes reliably under load, for a named root cause, not a retry or a longer timeout.

## Scope
- It failed 3 of 10 on `rewrite` under load (TP-212's and TP-197's runs), and once in a TP-211 full lab, re-run green.
- It sleeps a fixed time (`time.Sleep(quiet)`, "all four accepted and routing") before it dials the member; under load the four idle connections may not have reached RouteStream's wait by then, so the member's connection meets a full routing bound. Confirm or refute this, and make the test wait on the state it means (each idle connection's slot freed) instead of a sleep, or fix the code if the bound is held longer than its contract says.

## Out of scope
- Other supervisor tests that sleep: one ticket per named flake.

## Acceptance
- [x] The root cause named in Notes, with the failing run's evidence.
- [x] A fix in the test or the code.
- [x] The test passes 20 runs under load (a full lab or SIGSTOP freezes beside it), and a mutation that brings the cause back fails it.
- [x] No retries and no longer timeouts without a cause.

## Notes
- **Root cause.** A race in the test, not in the code. `serveStreams` takes a connection's routing slot in the accept loop, before the connection's routing goroutine runs, and the slot is freed when that goroutine's `RouteStream` calls `waiting`. That is the bound as documented: a connection is in its routing work from its accept until it waits. The test dialled its four idle connections back to back and then slept `quiet`, assuming each had freed its slot in time. Under load the four sat in the listen backlog until the accept loop ran, which then accepted them back to back. The third and fourth found both slots (routingLimit 2) held by goroutines that had not yet run, so they went to the camouflage (`StreamsOverloaded` 1 or 2) while the member was still routed. Less often the idle connections' goroutines had not reached `waiting` by the end of the sleep, and the member itself was turned away ("the member was never handed over", the ticket's guess). Both cases have the same cause: the test assumed scheduling would happen within a fixed time. Production (1024 slots) behaves as its doc says: a burst of more than the bound arriving before the routing goroutines run is an overload.
- **Evidence.** Load: the test pinned with `taskset` to two cores beside four busy loops pinned to the same cores, the test at nice 19 (plain busy loops at equal priority, or GOMAXPROCS=1, failed 0 of 100). On 0743eef (rewrite, unfixed), 12 of 300 failed:
  ```
  7  shared_test.go:1562: listener {ID:1 Transport:line Address:127.0.0.1:0 Routed:1 Unauthenticated:0 NoSpace:0 StreamsOverloaded:1 StreamsBoundClosed:0 Rejected:[]}
  4  shared_test.go:1562: listener {ID:1 Transport:line Address:127.0.0.1:0 Routed:1 Unauthenticated:0 NoSpace:0 StreamsOverloaded:2 StreamsBoundClosed:0 Rejected:[]}
  1  shared_test.go:1559: the member was never handed over
  ```
  `Routed:1` with `StreamsOverloaded` above 0 means an idle connection was turned away, not the member: the overload happened at an accept while both slots were held by connections that had not yet waited. A deterministic stand-in for the load (the test transport sleeping 100 ms before calling `waiting`, as a routing goroutine that runs late) makes the unfixed test fail every time with the same counters (`Routed:1 StreamsOverloaded:2`).
- **Fix (test only, shared_test.go).** The test transport reports on a channel once a connection's `waiting` has returned. The test dials each idle connection only after the previous one has reported, so its slot is known to be free. The `time.Sleep(quiet)` is gone. The test still holds four idle connections (more than the bound) while the member is routed, and still requires `StreamsOverloaded` 0. No product code changed.

## Log
- 2026-11-15 created in backlog (from TP-211's and TP-197's lab runs)
- 2026-11-16 backlog → in-progress, owner: agent-tp-221
- 2026-11-16 diagnosis: under the pinned load in Notes the unfixed test failed 2 of 100 on 4599c00 and 12 of 300 on 0743eef (11 with idle connections turned away and the member routed, 1 with the member turned away); 0 of 100 with plain busy loops or GOMAXPROCS=1
- 2026-11-16 fix (24ac290, test only): each idle connection is dialled once the previous one's waiting has returned; the sleep is removed. No product code changed
- 2026-11-16 mutations, each failed the fixed test and was restored: M1, the four idle connections dialled together again with the test transport sleeping 100 ms before waiting (the cause brought back), failed 3 of 3 ("idle connection 3 never waited", StreamsOverloaded 2); M2, the supervisor ignoring waiting (routeStream given a no-op), failed ("idle connection 3 never waited", StreamsOverloaded 1). With the 100 ms delay alone, the fixed test passed 20 of 20 and the unfixed test failed 3 of 3 with Routed 1, StreamsOverloaded 2
- 2026-11-16 runs on 24ac290: under the same pinned load, the fixed test passed 300 of 300 (load average 12 to 15); `make lab-gotest PKG=./internal/agent/supervisor RUN='TestIdleStreamsDontStarveRouting$' COUNT=20` beside six busy loops passed 20 of 20 (GOFLAGS=-p=2, LAB_P=1); `make lint` and `make test` green (umask 022)
- 2026-11-16 merged origin/rewrite at b9ee06d (e931769, tickets only, no Go). Full `make lab-test` skipped: this ticket changes only a test, no lab-tested code
- 2026-11-16 in-progress → review
