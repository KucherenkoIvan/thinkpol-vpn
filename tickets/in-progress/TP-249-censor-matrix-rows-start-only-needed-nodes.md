---
id: TP-249
title: "Censor-matrix rows start only the nodes they need"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-242, TP-236]
refs: []
owner: "agent-tp-249"
branch: "tp-249-matrix-row-nodes"
---

## Goal
The owner wants a full lab to take at most 15 minutes on the remote runner (2026-11-16); after the lab-speed tickets the default stream still took ~36 minutes (TP-239's measurement, 2026-11-19). Each matrix row still starts all 7 upstream nodes (63 starts per run); some rows may not need device-b or server-2 (TP-242's out-of-scope note).

## Scope
- Per row, list the nodes its cells drive.
- Use Topology.Only (TP-242) for the rest dropped.
- Keep every verdict.

## Out of scope

## Acceptance
- [ ] Container starts of the matrix, before and after, in Notes.
- [ ] RESULTS.md verdicts identical (diff).

## Notes

## Log
- 2026-11-19 created in backlog (lab-speed follow-ups)
- 2026-11-19 backlog → in-progress, owner: agent-tp-249
