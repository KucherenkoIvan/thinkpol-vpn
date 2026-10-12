---
id: TP-055
title: "Make tests robust under parallel lab load"
milestone: M1
area: lab
repo: thinkpol-vpn
size: M
depends_on: [TP-002, TP-012]
refs: [DESIGN#censor-lab]
owner: "agent-flakes"
branch: "tp-055-test-robustness"
---

## Goal
`make lab-test` passes reliably while several agents run labs on the same host at once (host load around 28). Today several tests fail intermittently under load in code nobody changed and pass on a rerun, and every rerun costs a full lab run. Each flaky test either becomes deterministic, moves its performance-dependent threshold to `make lab-perf`, or (for statistical tests) uses enough samples that a false failure is negligible, without weakening what it proves.

## Scope
- Root-cause and fix the known flakes:
  - `internal/agent/supervisor` `TestSharedListenerThroughput` (24% loss vs its 20% functional limit in lab-test mode)
  - `internal/dataplane/netcfg` `TestDefaultRoute`
  - `internal/dataplane/transport/udp` `TestPaddingHidesPacketSizes`
  - `internal/dataplane/transport/transporttest` many-concurrent-links lost a datagram under `-race` (TP-010 note)
- Scan the rest of the tests for timing sensitivity (fixed sleeps, tight timeouts, exact counts over lossy paths, statistical thresholds with small samples) and fix what's found the same way.
- If a test was catching a real bug, fix the product and say so.
- Decide whether `make lab-test` should limit its own in-node package parallelism under high host load; document the decision.

## Out of scope
Earlier flakes already fixed: `TestWorkersAreSandboxed` (TP-054), `TestCommandStartsSealed` (TP-054), the agent map-watcher test (TP-017). Product areas being worked in parallel (TP-014 egress, TP-018 route table, TP-020 DNS) beyond their test files.

## Acceptance
- [ ] every listed flake: cause found in the code, fixed (deterministic, perf-gated, or statistically sound), cause → fix in Notes
- [ ] scan of other timing-sensitive tests done; findings fixed or noted as fine
- [ ] in-node package parallelism under load decided and documented
- [ ] each fixed test run with a high `-count` (20–50) inside lab nodes, green
- [ ] one full `make lab-test` green while another lab is running
- [ ] `make lint`, `make test` green

## Notes

## Log
- 2026-10-12 created in in-progress — owner: agent-flakes, branch: tp-055-test-robustness
