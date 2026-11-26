---
id: TP-290
title: "Two lab tests fail at real WireGuard timers"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: [docs/design/path-liveness.md#busy-links, docs/design/path-liveness.md#idle-and-double-failure, RR48]
owner: ""
branch: ""
---

## Goal
The M2 gate needs a green full lab at real WireGuard timers (`THINKPOL_LAB_WG_TIMER_SCALE=1 make lab-test`, lab/README.md "WireGuard's timers"). A real-timer full lab on rewrite 441e536e (2026-11-26) exited 1 on two tests that pass at the lab's default ÷10 timers. When this is done, each of them asserts what the design or the health rules promise at any timer scale, and both pass at real timers.

1. `TestLinksUnderTraffic` (lab/liveness_test.go; TP-080, docs/design/path-liveness.md), "cut both ways" under pings. device-a closes 2–3 s after its last answer every time, but server-1 closes far later than the test's busy bound (4.5 s, plus 1.5 s of load slack):

   | cell | full lab | targeted re-run at scale 1 |
   |---|---|---|
   | udp | 10.19 s | 6.97 s |
   | reality | 17.82 s | 16.43 s |
   | reality, server-1's side under device-a's one-way stream | 18.43 s | 18.68 s |

   Suspect: the design's busy bound holds "at any end still sending". After the cut server-1 gets no pings, so it sends nothing and falls under the idle rule (dead-idle bound 16 s on `udp`, 26 s on `reality`). At ÷10 timers something WireGuard sends on its own kept server-1 sending, so the busy bound applied by accident. If so, the product matches the design and the test's oracle for server-1 is wrong at scale 1.
2. `TestHealthWithAnExitThatNeverHandshakes` (default stream): `health_test.go:111: not within 1m30s: health ok [], want down`. It passed a targeted scale-1 re-run in 69 s. Suspect: the 90 s window is too tight at real timers under load. Check what the product promises (`dataplane.ExitHandshakeDeadline` = 3 × REKEY_TIMEOUT, the health rules, RR48) and what the window should be at scale 1.

## Scope
- Diagnose both from a scale-1 run's logs: link close lines (reason, last_answer, packet counts), the path counters, and what WireGuard sends.
- If the product matches the design: fix only the test oracles (and setup). For each end, assert the bound for whether it is still sending (busy) or not (idle), as the design states. device-a's busy bound stays exactly as it is.
- Docs that describe the tests (docs/design/path-liveness.md "Lab, as built", lab/README.md if it says so).

## Out of scope
- Product or design changes. If the product breaks a bound the design states, the ticket says so and stops for the orchestrator.
- The real-timer full lab: the orchestrator runs it after the merge.

## Acceptance
- [ ] (a) For each failure, the cause is shown with log lines from a scale-1 run: whether server-1 was sending after the cut, and which rule closed it.
- [ ] (b) Each test asserts the bound the design or the health rules actually promise for that end at any timer scale. Name the design line. Each has a named mutation that still fails it.
- [ ] (c) Targeted scale-1 runs of both tests pass, 3 times each, plus one at the default scale.
- [ ] (d) If the product, not the oracle, breaks a stated bound, the ticket says so and stops for the orchestrator.

## Notes
- Found in the real-timer full lab on rewrite 441e536e (2026-11-26, exit 1). Every other test passed there.

## Log
- 2026-11-26 created in backlog (found in a real-timer full lab on 441e536e)
