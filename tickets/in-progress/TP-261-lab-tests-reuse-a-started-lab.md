---
id: TP-261
title: "Lab tests reuse a started lab instead of starting their own"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: L
depends_on: [TP-260]
refs: []
owner: "agent-tp-261"
branch: "tp-261-lab-reuse"
---

## Goal
Most lab tests start a fresh lab (4–7 containers) that lives seconds to a minute, so a run spends most of its time starting labs (57 starts × ~1 min in a warm run). TP-240 showed a reset+check between users of one lab is reliable (the matrix rows). The owner wants a full lab to take at most 15 minutes on the remote runner. Measured 2026-11-19 on rewrite cb0348d6 with every lab-speed ticket merged: 23m12s cold and 23m8s with the node phase fully cached; all tests passed; the lab/ package alone took ~22 minutes; lab slot waits median 60–73 s, max 9–11 min; `docker compose up` per lab median 46–78 s; 57–111 lab starts per run.

## Scope
- A small pool of started labs per topology that tests take, use, and return after a verified reset (TP-240's snapshot/reset/check).
- Tests that must have a fresh lab are marked and keep getting one.
- Start with the most common topologies.

## Acceptance
- [ ] Lab starts per full lab, before and after, in Notes (target: at least halved).
- [ ] Every reused lab passes the reset check before the next test gets it; a failed check retires that lab (test).
- [ ] Full-lab wall time before and after, in Notes.

## Notes

## Log
- 2026-11-19 created in backlog (full-lab measurement on rewrite cb0348d6)
- 2026-11-19 backlog → in-progress, owner: agent-tp-261
