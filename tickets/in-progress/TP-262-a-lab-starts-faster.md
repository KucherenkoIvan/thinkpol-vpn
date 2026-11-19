---
id: TP-262
title: "A lab starts faster"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: "agent-tp-262"
branch: "tp-262-faster-lab-start"
---

## Goal
`docker compose up` takes 46–78 s median per lab on the remote runner, longer under load. The owner wants a full lab to take at most 15 minutes on the remote runner. Measured 2026-11-19 on rewrite cb0348d6 with every lab-speed ticket merged: 23m12s cold and 23m8s with the node phase fully cached; all tests passed; the lab/ package alone took ~22 minutes; lab slot waits median 60–73 s, max 9–11 min; `docker compose up` per lab median 46–78 s; 57–111 lab starts per run.

## Scope
- Measure where a lab start's time goes: image layers, container create, network create, the `--wait` health checks, the node's own boot.
- Cut it (e.g. a lighter node image, health checks that watch state instead of polling intervals, pre-created networks, parallel container start), keeping every lab test's claims.

## Acceptance
- [ ] Breakdown of a lab start before and after, in Notes.
- [ ] Median lab start halved on the remote runner (timeline).
- [ ] No lab test changes what it proves.

## Notes

## Log
- 2026-11-19 created in backlog (full-lab measurement on rewrite cb0348d6)
- 2026-11-19 backlog → in-progress, owner: agent-tp-262
- 2026-11-19 TP-267 folded in (orchestrator): the slot-to-lock gap is the read of the daemon's subnets; moving it before the slot
