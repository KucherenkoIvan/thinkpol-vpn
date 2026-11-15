---
id: TP-227
title: "Flaky TestRealityEndpointsLinkANodeAndADevice"
milestone: M2
area: devmap
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-227"
branch: "tp-227-flaky-devmap-reality-endpoints"
---

## Goal
`TestRealityEndpointsLinkANodeAndADevice` (internal/devmap/plan_reality_test.go:79, from TP-201) failed under load with "t.Error after the test returned" (a goroutine reporting after the test ended).

## Scope
- Find the goroutine, make the test wait for it, or fix the code if it outlives its owner.

## Out of scope

## Acceptance
- [ ] The root cause named in Notes, with the failing run's evidence.
- [ ] A fix in the test or the code.
- [ ] The test passes 20 runs under load (a full lab or SIGSTOP freezes beside it), and a mutation that brings the cause back fails it.
- [ ] No retries and no longer timeouts without a cause.

## Notes

## Log
- 2026-11-16 created in backlog (from the M2 gate review)
- 2026-11-16 backlog → in-progress, owner: agent-tp-227
