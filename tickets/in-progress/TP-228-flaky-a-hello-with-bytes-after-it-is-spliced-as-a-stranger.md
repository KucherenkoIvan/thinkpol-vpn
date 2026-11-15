---
id: TP-228
title: "Flaky TestAHelloWithBytesAfterItIsSplicedAsAStranger"
milestone: M2
area: dataplane/transport/reality
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-228"
branch: "tp-228-flaky-reality-hello-stranger"
---

## Goal
`TestAHelloWithBytesAfterItIsSplicedAsAStranger` (internal/dataplane/transport/reality/router_test.go:297) failed under load with "verdict 4, want StreamUnknown" after TP-201 fixed a clock flake in it.

## Scope
- Find why the verdict differs under load.

## Out of scope

## Acceptance
- [ ] The root cause named in Notes, with the failing run's evidence.
- [ ] A fix in the test or the code.
- [ ] The test passes 20 runs under load (a full lab or SIGSTOP freezes beside it), and a mutation that brings the cause back fails it.
- [ ] No retries and no longer timeouts without a cause.

## Notes

## Log
- 2026-11-16 created in backlog (from the M2 gate review)
- 2026-11-16 backlog → in-progress, owner: agent-tp-228
