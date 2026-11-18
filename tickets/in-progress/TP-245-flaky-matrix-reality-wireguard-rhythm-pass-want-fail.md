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
- [x] The root cause named in Notes, with evidence.
- [x] A fix.
- [ ] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [x] No retries and no longer timeouts without a cause.

## Notes
- **Root cause: the count signal's chain was tuned to the clean trace, and load breaks it; the burst signal, which caught most runs, loses rekeys under load too.** In TP-243's run at 3d2f04d8 (four tickets' labs on the runner) both missed. That run's summary rules out the other suspects: the held connection (one TLS connection, all 7m48s) carried 605 records device→server and 608 back, the same +3 after the TLS start as caught runs (each rekey leaves the device one record ahead: three rekeys happened, at ~120, 240, 360 s of a 450 s hold), and the hold's pings came back 225 of 225 (busy throughout). Its per-record trace wasn't kept (a full lab runs without THINKPOL_LAB_TRACES), so which of the two ways below broke the count that run can't be shown; both are measured and fixed.
- Evidence, 13 traced lab runs of the reality rhythm cell under load (load average 0.6 to 20 where sampled, other tickets' labs beside them in all but one; replayed offline through both signals as they were):
  - The burst signal lost a rekey in 2 of 13 (a trigger ping's answer 93 ms late merging into the handshake, 2 records against 2; the device's confirming keepalive 54 ms after the response, past the 10 ms gap), leaving the count alone to catch the cell (one of those is a proof run below, caught by the count).
  - The count's steps came 120.13 to 120.92 s apart (13 runs; 120.3 and 120.6 s on the testdata trace) against a lower bound of exactly REKEY_AFTER_TIME (120 s): a margin of 0.13 to 0.92 s. A step is timed by the first record after 300 ms of quiet, which under load came up to 0.34 s before the handshake's records (a probe and a late ping with no 300 ms gap between them and the rekey; 0.21 s and 0.05 s in two others). A later step timed early by more than the margin restarts the chain: pass.
  - The count reads a level after 300 ms of quiet; an answer later than that is read as a step and its return as another (+1, then −1), which restarts the chain too. No answer that late on these 13 runs; it is the round trip TP-223's own comment named as the count's miss.
- Reproduced (lab/censor TestWGRhythmRealityTrace, the committed reality trace with the server's records 20 ms later so only the count can fire): one server record 400 ms late at 180 s, or three probe exchanges 250 ms apart right before the third rekey (its step timed 0.75 s early, 119.9 s after the second): the old rule passes both, the new one catches both at 363.6 s.
- Fix (lab/censor/modules_wgrhythm.go): wgCountHold, a difference read off the level is a step only once it has stayed off for 2 s (the time an answer has, wgPairWindow), so a late answer is no step; wgCountSlack, a count step chains from 2 s under a rekey period (118 s) to the window, for its timing. Both are choices, named so (doc.go keeps six numbers: both reuse the 2 s an answer has). The burst signal is unchanged: it times a burst by its own first record, and a handshake's initiation follows the previous response at the censor by at least REKEY_AFTER_TIME. The detector still reads WireGuard's handshake: TestWGRhythmRandomExchanges' pinned false-positive counts are unchanged (0 of 180 at 1 to 50 requests a second), steps 117 s or 60 s apart, of other sizes, or with the count moving between them still pass, and udp is still caught.
- What it costs: the count flags 2 to 4 s after the third rekey instead of on the next reading. The hold and the cell stay as they were: three rekeys come by ~362 s of the 450 s hold in every run seen.
- Proof at 2851a0ed (the code as merged; later commits are docs and the board): 10 lab-gotest runs of TestCensorMatrix udp and reality × off and wireguard-rhythm, one after another, each beside other tickets' labs (runs 1–7 and 9–10; load at 4 minutes in 20.1, 10.3, 9.0, 11.0, 11.7, 3.1, 0.6, 6.3, 6.8, 6.4) and, for runs 9 and 10, uncached go test of the module at 6 CPU slots beside them: reality failed as expected in 10 of 10 (9 by burst, 1 by count after the burst lost the first rekey), udp caught in 10 of 10, every off cell passed; 545–812 s a run.

## Log
- 2026-11-18 created in backlog (seen in TP-243's full labs)
- 2026-11-18 backlog → in-progress, owner: agent-tp-245
- 2026-11-18 traced the reality rhythm cell under load (THINKPOL_LAB_TRACES, 3 runs at 2276aff5, the detector as merged): caught each time, count steps 120.6–120.9 s apart, one step timed 0.34 s early, the burst losing a rekey once; numbers in Notes
- 2026-11-18 count signal: wgCountHold (a move off the level is a step after 2 s) and wgCountSlack (steps chain from 2 s under a rekey period); tests: TestWGRhythmRealityTrace "an answer 400 ms late", "probes right before the third rekey"; TestWGRhythmCountsRecords "an answer 400 ms late", "steps 119 s apart" (caught), "steps 117 s apart" (passes); doc.go, lab/README.md
- 2026-11-18 mutations, each killed (targeted go test of lab/censor on the development machine, restored after): wgCountHold 0 (both "400 ms late" cases); wgCountSlack 0 (TestWGRhythmCountsRecords "steps 119 s apart", TestWGRhythmRealityTrace "probes right before the third rekey"); wgCountSlack 4 s (TestWGRhythmCountsRecords "steps 117 s apart"); a reading back on the level not clearing the move (both "400 ms late" cases)
- 2026-11-18 make lint and make test pass at 87aa62e1 (TestWGRhythmRandomExchanges' pinned counts unchanged)
- 2026-11-19 10 lab-gotest runs at 2851a0ed of udp and reality × off and wireguard-rhythm under load: reality's expected fail 10 of 10 (9 burst, 1 count), udp caught 10 of 10; Notes
- 2026-11-19 not done: the full make lab-test (dropped by the orchestrator, 2026-11-18: concurrent full labs starve each other; targeted runs instead); 20 runs (the brief asked for 10, so the third box stays open); not verified: which of the two ways broke the count in TP-243's run (its trace wasn't kept); the hold needs no change
