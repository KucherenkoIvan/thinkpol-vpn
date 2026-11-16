---
id: TP-243
title: "Node-phase results are cached per test binary"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: "agent-tp-243"
branch: "tp-243-node-phase-cache"
---

## Goal
Unchanged packages aren't rerun in nodes. The owner wants a full lab to take at most 15 minutes on the remote runner. Measured 2026-11-16: a clean full lab takes 2823 s, and the remote runner's Docker starts only ~18–20 containers a minute, while a run starts 836 containers: the censor matrix 574 of them in 90 labs, each cell in use only 5–30 s.

## Scope
- labctl keeps a pass record keyed by sha256 of the test binary, the lab image tag, the hash of the package's testdata and `/src` inputs it reads, and the args/env.
- A package whose key passed on this machine is skipped and reported as `(cached)`; `-count=1` or `LAB_NOCACHE=1` forces a run.
- The make test host cache already works (161 s → 1 s).

## Out of scope

## Acceptance
- [ ] A second `make lab-test` on an unchanged tree shows every node package `(cached)` and starts no gotest lab. Evidence: the log and `docker events`.
- [ ] A changed testdata file reruns its package. Evidence: a log.

## Notes
- Saving: up to 639 s of node lab time and 41 starts (≈ 2.5 min of Docker time) on typical branches.

## Log
- 2026-11-16 created in backlog (owner: lab fixes, top priority; from the lab-speed audit)
- 2026-11-17 backlog → in-progress, owner: agent-tp-243
