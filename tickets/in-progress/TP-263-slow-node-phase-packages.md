---
id: TP-263
title: "Slow node-phase packages: packettest, routetable, path"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: agent-tp-263
branch: tp-263-slow-node-packages
---

## Goal
Cold, internal/dataplane/packettest took 8m31s, internal/dataplane/routetable 7m49s and internal/dataplane/path 7m33s in the node phase; a node cache miss on any of them takes half the budget. The owner wants a full lab to take at most 15 minutes on the remote runner. Measured 2026-11-19 on rewrite cb0348d6 with every lab-speed ticket merged: 23m12s cold and 23m8s with the node phase fully cached; all tests passed; the lab/ package alone took ~22 minutes; lab slot waits median 60–73 s, max 9–11 min; `docker compose up` per lab median 46–78 s; 57–111 lab starts per run.

## Scope
- Find where each package spends its time: fixed sleeps, real timers that could be sped up or injected, serial subtests that could be parallel, per-test setup.
- Cut it without weakening what the tests prove (TP-241's rules: watch state, speed up clocks).

## Acceptance
- [ ] Per-package time before and after (cold) in Notes.
- [ ] Each of the three under 3 minutes cold, or the reason it can't be.
- [ ] No test weakened: mutations named for any changed oracle.

## Notes

## Log
- 2026-11-19 created in backlog (full-lab measurement on rewrite cb0348d6)
- 2026-11-19 backlog → in-progress, owner: agent-tp-263
