---
id: TP-214
title: "An agent test that links stay up under steady WireGuard traffic, at production path timings"
milestone: M3
area: agent
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-210]
refs: []
owner: ""
branch: ""
---

## Goal
Some agent test asserts that links stay up over time under steady WireGuard traffic. None does any more: TP-210 dropped `no_link_up` and `neighbor_down` from the exit test's steady step, because the tests' 1 s path DeadAfter (fastPaths) re-dials links on a loaded machine.

## Scope
- A test with production path timings (or timings no tighter than production's ratio of DeadAfter to probe interval) that sends steady traffic through a device's link for several DeadAfter periods and asserts the link never closes and health raises neither `no_link_up` nor `neighbor_down`.
- Its run time kept reasonable; it may be lab-only if it is long.

## Out of scope
- Changing fastPaths for the other agent tests.
- The exit grading (TP-212, TP-213).

## Acceptance
- [ ] The test exists and passes 20 times in a lab node with the machine loaded; evidence: the `make lab-gotest … COUNT=20` run in the Log.
- [ ] A mutation that makes the path close a live link (a DeadAfter shorter than the probe interval, say) fails it; evidence: the Log.
- [ ] `make lint`, `make test` and `make lab-test` pass.

## Notes
- Source: TP-210 (R1.1 and its Notes, "Not fixed: a re-dial storm"): with freezes up to 1 s, fastPaths closed the link every 2 s or so.

## Log
- 2026-11-14 created in backlog (from TP-210)
