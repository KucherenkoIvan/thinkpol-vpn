---
id: TP-245
title: "Flaky matrix cell reality × wireguard-rhythm: pass, want fail"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-245"
branch: "tp-245-reality-rhythm-miss"
---

## Goal
In TP-243's second full lab at 3d2f04d8 (2026-11-18) the cell TestCensorMatrix/reality/wireguard-rhythm scored pass, want fail: the counting rules (TP-223) didn't flag reality's rekey that run. Either the hold missed a rekey (timing under load), or the rules' windows or quiet period miss it under load. This is the M2 gate's honest rhythm check, so a miss is as wrong as a false alarm. Find why from the run's verdict detail.

## Scope
- Reproduce, name why the rhythm rule passed reality that run, and fix the cause (the hold, the rules or the test's timing).

## Out of scope

## Acceptance
- [ ] The root cause named in Notes, with evidence.
- [ ] A fix.
- [ ] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [ ] No retries and no longer timeouts without a cause.

## Notes

## Log
- 2026-11-18 created in backlog (seen in TP-243's full labs)
- 2026-11-18 backlog → in-progress, owner: agent-tp-245
