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
owner: "agent-tp-290"
branch: "tp-290-real-timer-oracles"
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
- [x] (a) For each failure, the cause is shown with log lines from a scale-1 run: whether server-1 was sending after the cut, and which rule closed it. Liveness: the test now logs, from the router's capture, what server-1 sent once the blackhole was in force. At scale 1 on `udp`, only its 92 B probe, second probe and close notice, at +10.4 s, +11.1 s, +11.7 s (others: +5.9/6.5/7.1 s, +7.1/7.7/8.3 s): nothing of its own, and the idle rule closed it (idle wait 5.9–10.4 s, within 5–14 s). On `reality` the stream stalls, so the wire carries only retransmissions of what was sent before the cut ("0 new") and new frames wait behind them; server-1 closed at 17.2–17.6 s in four of six runs. That is WireGuard's handshake retry (15–15.33 s after its last reply) opening a burst, the sparse-sender rule. One run closed at 9.26 s, before the retry: the idle rule. At ÷10 the capture shows why it passed: WireGuard's initiation (248 B on `udp`) at +1.5 s and every 0.53 s, then the probes, so the sparse-sender rule closed it at 3.6–4.4 s, inside the busy bound by accident. Health: the failed run's status shows the exit handshook at 17:42:03.662, 1 ms after server-1's new link to server-2 came up with 2 frames in (its dial probe and the relayed initiation). server-2 started last (nodes start in map order). A link writes V1 frames, without seq and ack, until it learns the far end reads acks, so that initiation was 8 bytes shorter than the one length the nft rule dropped. The 90 s window was not the problem.
- [x] (b) Each test asserts the bound the design or the health rules actually promise for that end at any timer scale. Name the design line. Each has a named mutation that still fails it. Liveness (`serverBoundBothWays`, lab/liveness_test.go): server-1 is not "an end still sending" after the cut (path-liveness.md "Busy links"), so it gets the idle bound ("A dead idle link is found within I_max + T") or, if WireGuard's retry comes first, that retry plus the busy bound ("Sparse sender ... dead at a + X + 2.0–4.5 s"), whichever is lower: 16 s on `udp` and 19.8 s on `reality` at real time, 6.0 s at ÷10, plus the 1.5 s load slack. device-a's busy check is unchanged. Mutation "listening ends skip the busy rules" (`wroteLocked` returns for `!l.dialed`) fails at ÷10 on server-1 only (`udp` 14.1 s, `reality` 18.9 s, want within 6.03 s): `reality` every run, `udp` in about 86% of runs (it misses when server-1's idle wait draws under about 6.3 s). Health (`exitNoHandshakeBound`, lab/health_test.go): the health rules' 15 s (3 × REKEY_TIMEOUT, from the first initiation since the first hop came up; RR48, the health row of api-overview.md), plus one REKEY_TIMEOUT for that first initiation, scaled, plus 10 s of poll and load slack, counted from the first hop seen up (30 s at real time, 12 s at ÷10). The filter also drops the V1-frame initiation. Mutation `ExitHandshakeDeadline = 30 * wg.RekeyTimeout` fails it at ÷10 (`not within 12s: health ok [], want down`).
- [x] (c) Targeted scale-1 runs of both tests pass, 3 times each, plus one at the default scale. Scale 1, COUNT=3: passed on bf1a7bee (297 s) and again on the final test code 091b6287 (296 s). exit_no_handshake came 15.3–16.0 s after the first hop was seen up (bound 30 s); server-1's close is in (a). Default scale on 091b6287: passed (113 s), exit_no_handshake at 2.6 s (bound 12 s), server-1 at 3.98 s and 4.26 s (bound 6.03 s).
- [x] (d) If the product, not the oracle, breaks a stated bound, the ticket says so and stops for the orchestrator. Not the case: every close measured is within the bound the design states for that end, and health went down within the health rules' 15 s. Only the test oracles and the health test's filter were wrong.

## Notes
- Found in the real-timer full lab on rewrite 441e536e (2026-11-26, exit 1). Every other test passed there.
- The orchestrator's hypothesis held for the liveness test, with one refinement. What kept server-1 "sending" at ÷10 was WireGuard's handshake retry (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT after data sent with nothing back: 1.5 s scaled), not the passive keepalive, which expects no answer and starts no deadline. At real time the retry comes at 15 s, so server-1 falls to the idle rule unless the retry comes first.
- The reality one-way row (18.43 s, 18.68 s) never failed: the test already held server-1 there to the idle bound (26 s + slack). It's unchanged.
- The health test's 90 s window was never the cause. It's now the health rules' own bound (30 s at real time, 12 s at ÷10). The race also exists at ÷10, but there a retry every 0.5 s makes the V1-frame initiation rarely the current one.

## Log
- 2026-11-26 created in backlog (found in a real-timer full lab on 441e536e)
- 2026-11-26 backlog → in-progress, owner: agent-tp-290
- 2026-11-26 diagnosed from the real-timer full lab on 441e536e and scale-1 runs: server-1 sends nothing of its own after a cut both ways until WireGuard's retry (the oracle was wrong, not the product); the health test's filter missed the V1-frame initiation on a new link (a setup gap, not the window)
- 2026-11-26 lab/liveness_test.go: serverBoundBothWays, wgRetry, the router's capture of what server-1 sends after the cut (sentAfter); lab/health_test.go: both initiation lengths dropped, exitNoHandshakeBound; docs/design/path-liveness.md "Lab, as built" updated
- 2026-11-26 mutations: "listening ends skip the busy rules" (wroteLocked returns for !l.dialed) fails TestLinksUnderTraffic on server-1's bound at ÷10, the reality cell every run, the udp cell in about 86% of runs (it misses when server-1's idle wait draws under about 6.3 s); ExitHandshakeDeadline = 30 * wg.RekeyTimeout fails TestHealthWithAnExitThatNeverHandshakes at ÷10. Dropped as too weak: a burst's first frame setting no deadline still closed server-1 in 4 s through within-burst deadlines.
- 2026-11-26 runs: make lint, make test green on 091b6287; targeted lab-gotest of both tests at scale 1 COUNT=3 passed on bf1a7bee and 091b6287, at the default scale on 091b6287; no full lab (the orchestrator runs the real-timer full lab after the merge)
- 2026-11-26 not verified: which rule closes reality's server-1 can't be read off the wire (stalled TCP); it's inferred from timing (17.2–17.6 s fits the retry's burst; 9.26 s, the idle draw)
- 2026-11-26 in-progress → review
- 2026-11-26 review nits: exitNoHandshakeBound comment says what a changed deadline it catches; the udp mutation miss rate corrected above
