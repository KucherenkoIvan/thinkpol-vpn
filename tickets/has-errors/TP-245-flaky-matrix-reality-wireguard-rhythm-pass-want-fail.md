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
- Load that still breaks both signals (lab/censor's package doc): a rekey whose handshake is answered later than REKEY_TIMEOUT (a second initiation: the count steps by two, a whole burst holds one more record), which starts both chains over; and, together, a count that moves between rekeys (records one way nothing answers, an answer later than 2 s, or requests answered later than 300 ms leaving a different number in flight from one reading to the next: random requests at one a second answered 0.3 to 1.9 s later) with a burst broken by records within 10 ms of the handshake's or a handshake spread wider than 10 ms at the censor.

## Acceptance
- [x] Candidate causes measured on 13 traced runs and reproduced in unit tests; TP-243's own cause unverified: its trace wasn't kept.
- [x] A fix.
- [ ] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [x] No retries and no longer timeouts without a cause.

## Notes
- **Root cause: the count signal's chain was tuned to the clean trace, and load breaks it; the burst signal, which caught most runs, loses rekeys under load too.** In TP-243's run at 3d2f04d8 (four tickets' labs on the runner) both missed. That run's summary rules out the other suspects: the held connection (one TLS connection, all 7m48s) carried 605 records device→server and 608 back, the same +3 after the TLS start as caught runs (each rekey leaves the device one record ahead: three rekeys happened, at ~120, 240, 360 s of a 450 s hold), and the hold's pings came back 225 of 225 (busy throughout). Its per-record trace wasn't kept (a full lab runs without THINKPOL_LAB_TRACES), so which of the two ways below broke the count that run can't be shown; both are measured and fixed.
- Evidence, 13 traced lab runs of the reality rhythm cell under load (load average 0.6 to 20 where sampled, other tickets' labs beside them in all but one; replayed offline through both signals as they were):
  - The burst signal lost a rekey in 2 of 13 (a trigger ping's answer 93 ms late merging into the handshake, 2 records against 2; the device's confirming keepalive 54 ms after the response, past the 10 ms gap), leaving the count alone to catch the cell (one of those is a proof run below, caught by the count).
  - The count's steps came 120.13 to 120.92 s apart (13 runs; 120.3 and 120.6 s on the testdata trace) against a lower bound of exactly REKEY_AFTER_TIME (120 s): a margin of 0.13 to 0.92 s. A step is timed by the first record after 300 ms of quiet, which under load came up to 0.34 s before the handshake's records (a probe and a late ping with no 300 ms gap between them and the rekey; 0.21 s and 0.05 s in two others). A later step timed early by more than the margin restarts the chain: pass.
  - The count reads a level after 300 ms of quiet; an answer later than that is read as a step and its return as another (+1, then −1), which restarts the chain too. No answer that late on these 13 runs; it is the round trip TP-223's own comment named as the count's miss.
- Reproduced (lab/censor TestWGRhythmRealityTrace, the committed reality trace with the server's records 20 ms later so only the count can fire): one server record 400 ms late at 180 s, or probe exchanges 250 ms apart right before the third rekey (round 0: three, its step timed 0.75 s early; round 1: 3 s of them, before the third or before each), or the device's ping 2 s after the second rekey answered 400 ms late (round 1, read as a step of +2 by the round-0 hold): the rule before TP-245 passes them, the fixed one catches each after the third rekey.
- Fix as first reviewed (round 0): wgCountHold, a difference read off the level is a step only once it has stayed off for 2 s; wgCountSlack, a count step chains from 2 s under a rekey period (118 s). Review round 1 replaced both:
- Fix (lab/censor/modules_wgrhythm.go, readCount): a move off the level is a step once a reading finds the first or the latest value it was read at again wgCountHold (2 s, the time an answer has) after the records that took it there, so a late answer, even one read on top of the step, is no step (R1.1); a pending move is read again on any packet after 300 ms of quiet, so a quiet connection's step is confirmed before the next record is counted (R1.3); a step is timed as a span, from the first record of the run whose reading found the move (or of the run the on-level reading before read, when it ended within 2 s before: an answer in flight can have hidden the step from that reading) to the last record of the run that took the count to its new value, and spans chain when the newer ends at least REKEY_AFTER_TIME after the older began and begins within the rekey window of its end (R1.2). WireGuard's rekeys come REKEY_AFTER_TIME and a round trip or more apart, and the handshake lies in each span, so they chain however long the runs around them; wgCountSlack is gone. The 2 s of the hold and of the look-back are choices, named in doc.go with why. The burst signal is unchanged: it times a burst by its own first record, and a handshake's initiation follows the previous response at the censor by at least REKEY_AFTER_TIME. The detector still reads WireGuard's handshake: TestWGRhythmRandomExchanges' pinned counts are unchanged for answers within 80 ms, and its new band of answers 0.3 to 1.9 s later (where the hold runs) flags 6 of 600 at a request a minute and 3 of 60 at one a second, all by the rekey signal, none by the count or the burst (R1.4); TestWGRhythmImbalanceBesideTraffic pins the hold's risk: a record nothing answers every 150 s beside random one-for-one exchanges at a request a second is flagged by the count in 20 of 20 connections with answers within 80 ms and in 0 of 20 (1 by the rekey signal) with answers 0.3 to 1.9 s later, where the count's level is read with requests in flight; steps 119 s, 117 s or 60 s apart, of other sizes, or with the count moving between them pass, and udp is still caught.
- What it costs: the count flags 2 to 4 s after the third rekey instead of on the next reading, and steps that truly come under REKEY_AFTER_TIME apart chain when they are within their spans' length of it (steps 119 s apart under a ping every 2 s don't). The hold and the cell stay as they were: three rekeys come by ~362 s of the 450 s hold in every run seen.
- Proof of the round-0 code at 2851a0ed: 10 lab-gotest runs of TestCensorMatrix udp and reality × off and wireguard-rhythm, one after another, each beside other tickets' labs (runs 1–7 and 9–10; load at 4 minutes in 20.1, 10.3, 9.0, 11.0, 11.7, 3.1, 0.6, 6.3, 6.8, 6.4) and, for runs 9 and 10, uncached go test of the module at 6 CPU slots beside them: reality failed as expected in 10 of 10 (9 by burst, 1 by count after the burst lost the first rekey), udp caught in 10 of 10, every off cell passed; 545–812 s a run.

## Review findings
Round 1.

- [ ] R1.1 (should-fix) The hold doesn't protect the reading that confirms the step: a rekey at T, the next ping at T+2 s answered 400 ms late, the reading at T+2.3 s finds level+2 and records a step of +2, then the late answer reads −1 and the chain restarts. Remember the first off value and confirm only a reading that matches it; test: a 400 ms late answer to the ping right after a rekey.
- [ ] R1.2 (should-fix) The fixed 2 s slack is a guess: the timing error is how long the run of records before the rekey lasted (no 300 ms gap for more than 2 s, or a late answer in flight when the rekey lands). Time each step as a span (first record of the run that moved the level to the last record before it settled) and chain spans: continue when the newest span's end is at least the rekey interval after the previous span's start and its start is within the window of the previous span's end. Real rekeys are at least 120 s plus one round trip apart. Tests: gapless traffic for 3 s before each rekey is caught; steps that truly come under 118 s apart are not chained. A fixed slack kept anywhere is named in doc.go as the lab's own choice, with why.
- [ ] R1.3 (should-fix) On a quiet connection a move is only confirmed at the next reading, which includes the next exchange (one unanswered record every 120 s reads as +2 every 240 s). Re-read when a move is pending and its hold has passed, or document it; make lab/README.md's "flags a quiet connection that repeats one imbalance" true for the count signal, or fix the sentence.
- [ ] R1.4 (should-fix) TestWGRhythmRandomExchanges' answers all come within 80 ms, so the hold never runs: add a round-trip band of 0.3–1.9 s, pin its counts, state them in doc.go's false-positive paragraph.
- [ ] R1.5 (docs) doc.go and lab/README.md: the blind spot "round trips over 2 s" is wrong; state the real conditions after R1.1–R1.3. "2 to 3.5 minutes" / "120 to 210 s" → the actual lower bound. Add the blind spots that break both signals (a handshake answered later than REKEY_TIMEOUT; traffic landing within 10 ms of the handshake records).
- [ ] R1.6 (nit) The test's "steps 119 s apart" is not WireGuard timing: say the case pins the widened lower bound.
- [ ] R1.7 (ticket) Box 1 reworded to what was shown; "## Out of scope" lists the load that still breaks both signals; box 3: 20 lab runs of TestCensorMatrix udp and reality × off and wireguard-rhythm at the final head, ticked only on 20/20.

## Log
- 2026-11-18 created in backlog (seen in TP-243's full labs)
- 2026-11-18 backlog → in-progress, owner: agent-tp-245
- 2026-11-18 traced the reality rhythm cell under load (THINKPOL_LAB_TRACES, 3 runs at 2276aff5, the detector as merged): caught each time, count steps 120.6–120.9 s apart, one step timed 0.34 s early, the burst losing a rekey once; numbers in Notes
- 2026-11-18 count signal: wgCountHold (a move off the level is a step after 2 s) and wgCountSlack (steps chain from 2 s under a rekey period); tests: TestWGRhythmRealityTrace "an answer 400 ms late", "probes right before the third rekey"; TestWGRhythmCountsRecords "an answer 400 ms late", "steps 119 s apart" (caught), "steps 117 s apart" (passes); doc.go, lab/README.md
- 2026-11-18 mutations, each killed (targeted go test of lab/censor on the development machine, restored after): wgCountHold 0 (both "400 ms late" cases); wgCountSlack 0 (TestWGRhythmCountsRecords "steps 119 s apart", TestWGRhythmRealityTrace "probes right before the third rekey"); wgCountSlack 4 s (TestWGRhythmCountsRecords "steps 117 s apart"); a reading back on the level not clearing the move (both "400 ms late" cases)
- 2026-11-18 make lint and make test pass at 87aa62e1 (TestWGRhythmRandomExchanges' pinned counts unchanged)
- 2026-11-19 10 lab-gotest runs at 2851a0ed of udp and reality × off and wireguard-rhythm under load: reality's expected fail 10 of 10 (9 burst, 1 count), udp caught 10 of 10; Notes
- 2026-11-19 not done: the full make lab-test (dropped by the orchestrator, 2026-11-18: concurrent full labs starve each other; targeted runs instead); 20 runs (the brief asked for 10, so the third box stays open); not verified: which of the two ways broke the count in TP-243's run (its trace wasn't kept); the hold needs no change
- 2026-11-19 merged origin/rewrite (8a3b8850; TP-242's lab changes); at e9d5fbd0: make lint and make test pass; lab-gotest of udp and reality × off and wireguard-rhythm (other labs beside it): udp caught, reality's expected fail (burst), both off cells pass, 603 s
- 2026-11-19 handoff: nothing left running on the test machine; the run directories are outside the repo
- 2026-11-19 in-progress → review
- 2026-11-19 review round 1: fix R1.1–R1.7
