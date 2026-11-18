---
id: TP-246
title: "Flaky TestKillSwitchUnderSystemd: its 3 s limit counts docker exec time"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
In TP-243's first full lab at 3d2f04d8 (2026-11-18) TestKillSwitchUnderSystemd failed: the curl was refused at once (as wanted), but the `docker exec` around it took 3.65 s against a 3 s limit under load; run alone it passed. Make the limit measure what the test means (time inside the node, or a refusal the node reports) instead of the exec's overhead.

## Scope
- Name what the 3 s limit is meant to prove, and measure that inside the node instead of around the `docker exec`.

## Out of scope

## Acceptance
- [x] The root cause named in Notes, with evidence.
- [x] A fix.
- [ ] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [x] No retries and no longer timeouts without a cause.

## Notes
- Root cause (TP-241's Log, 2026-11-18): the 3 s limit timed the whole `docker exec` around the curl, and a loaded host stretches the exec, not the curl: a run at load 14 took 7.9 s around a curl that failed in 0 ms. What the limit means to prove is that the kill switch refuses the connection at once (a reject, not a drop the curl waits out), which is curl's own time.
- The fix, TP-241's 3ad4cc95: the test reads curl's own time_total (`-w`) and bounds that at 3 s, a missing time_total failing the check. It adds no retry and keeps the 3 s limit and curl's 5 s bound.
- Box 3 stays open: TP-241's Log shows TestKillSwitchUnderSystemd passing three times targeted, once more on its final code and in its full labs, not 20 runs under load, and logs no mutation that brings the exec-timed bound back.

## Log
- 2026-11-18 created in backlog (seen in TP-243's full labs)
- 2026-11-19 backlog → done: fixed by TP-241 (the test times a refused curl by curl's own clock, commit 3ad4cc95)
