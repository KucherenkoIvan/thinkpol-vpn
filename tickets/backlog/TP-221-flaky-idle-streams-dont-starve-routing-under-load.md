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
owner: ""
branch: ""
---

## Goal
`TestIdleStreamsDontStarveRouting` (internal/agent/supervisor/shared_test.go, from TP-201) passes reliably under load, for a named root cause, not a retry or a longer timeout.

## Scope
- It failed 3 of 10 on `rewrite` under load (TP-212's and TP-197's runs), and once in a TP-211 full lab, re-run green.
- It sleeps a fixed time (`time.Sleep(quiet)`, "all four accepted and routing") before it dials the member; under load the four idle connections may not have reached RouteStream's wait by then, so the member's connection meets a full routing bound. Confirm or refute this, and make the test wait on the state it means (each idle connection's slot freed) instead of a sleep, or fix the code if the bound is held longer than its contract says.

## Out of scope
- Other supervisor tests that sleep: one ticket per named flake.

## Acceptance
- [ ] The root cause named in Notes, with the failing run's evidence.
- [ ] A fix in the test or the code.
- [ ] The test passes 20 runs under load (a full lab or SIGSTOP freezes beside it), and a mutation that brings the cause back fails it.
- [ ] No retries and no longer timeouts without a cause.

## Notes

## Log
- 2026-11-15 created in backlog (from TP-211's and TP-197's lab runs)
