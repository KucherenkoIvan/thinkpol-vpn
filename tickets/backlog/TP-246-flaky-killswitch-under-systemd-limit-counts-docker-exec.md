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
- [ ] The root cause named in Notes, with evidence.
- [ ] A fix.
- [ ] 20 runs of the test under load pass, and a mutation that brings the cause back fails.
- [ ] No retries and no longer timeouts without a cause.

## Notes

## Log
- 2026-11-18 created in backlog (seen in TP-243's full labs)
