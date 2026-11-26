---
id: TP-289
title: "TP-080's blackout test fails a full lab when load stretches its own blackout"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: [docs/design/path-liveness.md#chains-code-tests]
owner: agent-tp-289
branch: tp-289-blackout-retry
---

## Goal
`TestLinksUnderTraffic`'s blackoutRiddenOut (lab/liveness_test.go) never fails a lab only because a loaded machine stretched the blackout the router holds: it retries a stretched blackout and judges liveness only on a try whose window held the band, so a red lab means a real liveness failure or a setup that never held.

## Scope
- blackoutRiddenOut: retry the blackout, fresh, after the link has recovered and pings flow again (a watcher, not a fixed sleep), up to a small bound; judge liveness (no link closed, the pings came back) only on a try whose measured windows held 1 to 1.25 s; fail as a broken setup only if no try held it. Log every try's windows.
- holdBlackout: cut the script's own spread where it's cheap (e.g. both interfaces in one `tc -batch` for the add and one for the del).
- Docs that describe the test (docs/design/path-liveness.md "Lab, as built", lab/README.md if it says so).

## Out of scope
- Widening the 1 to 1.25 s band: after an exact 1 s blackout the pings came back 1.4 to 1.8 s after the last answer, against a 2.0 s minimum S + R + T before a link closes, so a 1.4 s blackout can legitimately close a link.
- Other lab speed work.

## Acceptance
- [x] (a) A stretched blackout never fails the lab by itself: the test retries the blackout (fresh, after the link has recovered and pings flow again) up to a small bound, judges liveness only on a try whose measured window held the band, and fails as a broken setup only if no try held it. Mutation: no retry → a forced stretch fails it. blackoutRiddenOut retries up to blackoutTries (3), each retry after recovered (device-a's link up, then a ping across it, both watched); a forced stretch (sleep 3 s added to the first try's blackout) held 4.015 s on try 1, 1.009 s on try 2, and passed; with blackoutTries = 1 the same stretch fails: "broken setup, not a liveness failure: the blackout held 4.014s in 1 tries, want 1s to 1.25s".
- [x] (b) A close or lost pings during a try that held the band still fails the test (mutation: as TP-080's, S at its bottom and T = 0). With that mutation try 1 held 1.01 s and the test failed: device-a closed its link 757 ms after its last answer, server-1 closed too (468 of 566 pings back).
- [x] (c) The script's own spread is cut where it's cheap (e.g. both interfaces in one `tc -batch` for the add and one for the del); the measured windows are reported, quiet and loaded. holdBlackout writes both batch files before the blackout and runs one `tc -batch` for the add and one for the del, so both interfaces share one window, stamped before the add and after the del. Windows: 1.009 to 1.011 s in 5 quiet runs, 1.008 to 1.015 s in 5 beside a 6-process CPU burner (load about 7); before, 1.013 to 1.025 s (TP-080's measurements).
- [x] (d) The test stays within its current time when no retry happens; the worst case with retries is reported. No retry: the same 12 s of pings and 3 s lead, plus two file writes into the router before it; the reality subtest took 74 to 85 s quiet, 81 to 102 s loaded. One retry (the forced stretch, its first try 4 s) took the subtest to 105.5 s, about 20 s more. Worst case: two retries, each 12 s of pings plus the recovery watchers (60 s for the link, 60 s for a ping, at their limits), about 4.5 minutes more; seen, about 40 s.

## Notes
- TP-080 (merged as c73e4056): blackoutRiddenOut drops everything on the router for 1 s with netem, in one exec inside the router, stamped before each add and after each del; a window per interface, or as a whole, outside 1 to 1.25 s fails it as "broken setup, not a liveness failure".
- Measured 2026-11-26: quiet and targeted runs hold 1.013 to 1.025 s, even at load 14 to 15. In a full lab on c73e4056 (exit 2), eth1's window held 1.419 s and failed the test with every ping back; a targeted re-run passed. The guard works as designed, but a full lab's load can stretch the script itself (tc forks, date forks), and a red lab for a setup hiccup is a flake.

## Log
- 2026-11-26 created in backlog (found in TP-080's full lab runs)
- 2026-11-26 backlog → in-progress, owner: agent-tp-289
- 2026-11-26 blackoutRiddenOut retries a stretched blackout (up to 3 tries, each retry once device-a's link is up and a ping crosses it) and judges only a try within 1 to 1.25 s; holdBlackout adds and deletes both interfaces' netem in one tc batch each; docs/design/path-liveness.md "Chains, code, tests" updated
- 2026-11-26 runs on ecaf3150: make lint and make test passed; lab-gotest RUN=^TestLinksUnderTraffic$ COUNT=5 passed quiet (403 s, windows 1.009 to 1.011 s) and beside a CPU burner (453 s, windows 1.008 to 1.015 s, load about 7)
- 2026-11-26 lab mutations (a checkout, uncommitted, restored), lab-gotest RUN=^TestLinksUnderTraffic$/^reality$ on ecaf3150: (1) the first try's blackout stretched by 3 s → try 1 held 4.015 s, try 2 1.009 s, passed (the retry); (2) the same with blackoutTries = 1 → "broken setup, not a liveness failure: the blackout held 4.014s in 1 tries", failed; (3) S at its bottom and T = 0 → try 1 held 1.01 s, device-a closed its link (757 ms) and server-1 too, failed
- 2026-11-26 not verified: a full lab (the orchestrator runs one on rewrite after the merge); a natural stretch under a full lab's load was not reproduced, only forced
- 2026-11-26 in-progress → review
- 2026-11-26 review → done: merged into rewrite (review said merge, no defect)
