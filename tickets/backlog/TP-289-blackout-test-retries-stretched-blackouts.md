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
owner: ""
branch: ""
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
- [ ] (a) A stretched blackout never fails the lab by itself: the test retries the blackout (fresh, after the link has recovered and pings flow again) up to a small bound, judges liveness only on a try whose measured window held the band, and fails as a broken setup only if no try held it. Mutation: no retry → a forced stretch fails it.
- [ ] (b) A close or lost pings during a try that held the band still fails the test (mutation: as TP-080's, S at its bottom and T = 0).
- [ ] (c) The script's own spread is cut where it's cheap (e.g. both interfaces in one `tc -batch` for the add and one for the del); the measured windows are reported, quiet and loaded.
- [ ] (d) The test stays within its current time when no retry happens; the worst case with retries is reported.

## Notes
- TP-080 (merged as c73e4056): blackoutRiddenOut drops everything on the router for 1 s with netem, in one exec inside the router, stamped before each add and after each del; a window per interface, or as a whole, outside 1 to 1.25 s fails it as "broken setup, not a liveness failure".
- Measured 2026-11-26: quiet and targeted runs hold 1.013 to 1.025 s, even at load 14 to 15. In a full lab on c73e4056 (exit 2), eth1's window held 1.419 s and failed the test with every ping back; a targeted re-run passed. The guard works as designed, but a full lab's load can stretch the script itself (tc forks, date forks), and a red lab for a setup hiccup is a flake.

## Log
- 2026-11-26 created in backlog (found in TP-080's full lab runs)
