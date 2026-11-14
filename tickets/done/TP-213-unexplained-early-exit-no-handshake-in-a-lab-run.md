---
id: TP-213
title: "The unexplained 3.3 s exit_no_handshake in TP-048's lab run"
milestone: M2
area: agent
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-210]
refs: []
owner: "agent-tp-213"
branch: "tp-213-early-exit-no-handshake"
---

## Goal
The `exit_no_handshake` that TestAnExitThatNeverHandshakesIsExitNoHandshake raised 3.3 s into a run in TP-048's full lab (2026-11-12) has a named cause, reproduced with diagnostics on.

## Scope
- TP-210's mechanism (a re-dial, then WireGuard's next retry graded against the old pending initiation) needs a retry at least 5 s after the first initiation, so it doesn't explain a failure at 3.3 s. That run's log wasn't kept.
- Reproduce under load (the lab beside a full lab, or the SIGSTOP freezes TP-210 used) with a trace of what health is graded from (link up times, pending and last initiation, last handshake), and name the cause.
- Fix it here if it is the test's; if it is the grading's, file it with the evidence.

## Out of scope
- Retries or longer timeouts without a cause.
- TP-212's re-dial edge, unless the trace shows it is the same.

## Acceptance
- [x] The failure reproduced, or a bounded attempt that didn't reproduce it, with the trace or the run counts; evidence: the trace or counts in Notes.
- [x] The cause named in Notes with the trace lines that show it; evidence: the trace.
- [x] A fix with a mutation that brings the failure back, or a filed ticket for the grading; evidence: the Log.

## Notes
- Source: TP-210's Notes ("Not explained"). TP-210's earlier 1.3 s failures had no logs either; TP-210 left them to no_link_up's own tests if they were a second re-dial.
- **Which test failed.** TP-048's run was on 590e016, before TP-210's fix: its wait step broke out on health ok alone, and its steady step failed on any health but ok (status_test.go:1095 there).
- **Reproduced.** The 590e016 test body, with a temporary trace of what exit health is graded from and a temporary hook in report.statusWith timing the grading (both removed), run as a test binary frozen at random (SIGSTOP/SIGCONT, stops of 50 to 700 ms, gaps of 100 to 1000 ms, TP-210's method), on rewrite at d191d00: 11 of 60 failed. 8 were this ticket's symptom: `down`/`exit_no_handshake` in the steady step, 1.40 to 4.88 s into the test, the very read after the wait step's ok. 1 was TP-210's re-dial (ok after the link re-dialed at +2.63 s, down at the retry at +5.19 s). 2 were `no_link_up` in the steady step (a re-dial after the handshake, which TP-210's steady step now allows).
- **Cause: not a re-dial. The grading turns a duration measured at one moment into an instant with a later clock.** report.statusWith takes the engine's status, whose neighbors carry `UpFor` (how long the first hop has been up, measured when the status is read), then grades with `exitHandshakes(&st, time.Now(), …)`, which puts the link's coming up at `now - UpFor`. A stall between the two (load, here a freeze) moves that instant later by the stall's length. The test's first initiation leaves 6 to 13 ms after the link comes up, so a stall longer than that makes it look older than the link: "an initiation sent before its first hop came up isn't graded" (TP-195 R2.1), so that one read says ok with the exit unanswered. The old wait step broke out on it, and the next read, 1 ms later, was `down` again. The trace of a failing run (times from the test's start; "STALL" is the hook, "since" is the sampler's `now - UpFor`):
  ```
  +1.020s  first step: down [exit_no_handshake] unans=1 | link up since +0.002s | pending=+0.015s lastInit=+0.015s lastHS=-
  +1.022s  map 2 sent
  +1.397s  STALL status read at +1.246s graded at +1.397s (151ms later): unanswered=0 upFor=1.241s (graded up since +0.156s) pending=+0.015s lastInit=+0.015s
  +1.397s  wait step ok:  ok [] unans=0      | link up since +0.152s | pending=+0.015s lastInit=+0.015s lastHS=-
  +1.397s  steady step FAILS: down [exit_no_handshake] unans=1 | link up since +0.002s | pending=+0.015s lastInit=+0.015s lastHS=-
  ```
  The same link throughout: the device's log has one `link up` at the start and its `link closed` at the test's end, no re-dial. The other stall failures read the same way: graded at +2.197s, 328 ms after the read (graded up since +0.334s, the link up since +0.009s, failed at 2.20 s); graded at +4.870s, 676 ms after the read (+0.681s against +0.005s, failed at 4.88 s). A 3.3 s failure is this with a stall during the read at about 3.3 s. TP-210's unexplained 1.3 s failures fit as well (1.40 s here), since a stall just after map 2 is enough.
- **Why the current test doesn't fail.** TP-210's wait step also needs the exit's completed handshake (exitHandshook), which a stalled read doesn't fake, and the error only ever reads an exit as answered, never as unanswered, so its steady step can't fail on it. Under the same freezes the current test passed 30 of 30 on d191d00, and with the trace dumped on passing runs it passed 30 of 30 more while 19 of its reads in 14 runs were this false ok (the snapshot's link-up time at or before the last initiation, the graded one after it, the exit pending past the deadline).
- **What it means outside the test (for the grading, not fixed here).** One status read stalled longer than the gap between the first hop coming up and the exit's last initiation reports that exit answered. At production timings an exit is graded only after 15 s pending, and WireGuard initiates again every 5 s while it has traffic, so the gap is about 10 s or more by then, and the stall would have to be as long: a latent imprecision, not a symptom a member sees today. An exact grading takes the link's coming up from the snapshot's own clock: the status carries the moment it was read (or the path layer reports when each first hop came up), and exitHandshakes grades against that. TP-212 changes this comparison ("graded from the first initiation since the link came up"). As pushed so far (1e4f606, a test only) it doesn't cover it. Its fix covers it only if it takes the link's coming up from the snapshot rather than `time.Now() - UpFor`. Not filed: for the board, or for TP-212's review.

## Log
- 2026-11-14 created in backlog (from TP-210)
- 2026-11-15 backlog → in-progress, owner: agent-tp-213
- 2026-11-15 reproduced on rewrite at d191d00 with a temporary trace and a temporary timing hook in report.statusWith: the 590e016 test (TP-048's run) under random SIGSTOP freezes (stops of 50 to 700 ms) failed 11 of 60, 8 with this ticket's `exit_no_handshake` 1.40 to 4.88 s into the test (Notes)
- 2026-11-15 cause (Notes): exitHandshakes places the first hop's coming up at time.Now() minus the snapshot's UpFor, so a stall between reading the status and grading it makes an exit's initiation look older than its link and that read says ok; not a re-dial. In the grading, so not fixed here (TP-212's area); not covered by TP-212 as pushed (1e4f606)
- 2026-11-15 the test fix is TP-210's wait step (exitHandshook), already on rewrite: under the same freezes the current test passed 60 of 60 on d191d00 while 19 of its reads in 14 runs were the stalled false ok. Mutation: the wait step back to health ok alone failed 2 of 30, one with this cause (read at +1.702s, graded 235 ms later, the link graded up since +0.236s against a last initiation at +0.011s) and one with TP-210's re-dial
- 2026-11-15 no code changed (the trace and the hook removed; none earns a permanent place, the fix being in the grading), so no lab run. Not verified: a natural stall over 10 ms at that point in a lab node without freezes (the lab run's log wasn't kept). For the board: the grading imprecision in Notes, not filed (agents don't file tickets)
- 2026-11-15 `make lint` and `make test` green on d4d862b (umask 022)
- 2026-11-15 in-progress → review
- 2026-11-15 review (orchestrator): investigation accepted; the grading defect in Notes (link-up time graded against time.Now(), not the status read's time) is fixed in TP-212 (scope added from TP-213)
- 2026-11-15 review → done (merged)
