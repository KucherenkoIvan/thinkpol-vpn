---
id: TP-285
title: "./lab's in-node pass and the host-run packages never cache in a full lab"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-284]
refs: []
owner: "agent-tp-285"
branch: "tp-285-lab-and-host-run-cache"
---

## Goal
A second full `make lab-test` of the same commit, from another checkout, serves `./lab`'s in-node pass and the packages that need no node from their caches, as TP-284 made it serve the other in-node packages, so none of them spends the default stream's first minute on work already done.

## Scope
- `./lab`'s in-node pass is never recorded in a full lab, from any checkout: "pass not recorded: testcache: an input changed during the run: <checkout>/lab/bin". One of its tests reads the checkout's `lab/bin`, which the run's other phases write meanwhile (TP-284's two full labs of 18bfa3b3, both runs). About 40 s of node time and one node-phase lab start.
- The 16 packages that need no node run on the host under go test's own cache (TP-265/266), which keys on the checkout's path (the package directory in its build IDs without `-trimpath`, and the absolute names of the files a test opens), so a full lab from a fresh checkout runs them all (in TP-284's second run each took 20 s at most, all in the first minute).
- Fix minimally; a changed test, dependency or input still misses.

## Out of scope
- The node-phase key's checkout path (TP-284, done).
- The `lab/` phase's own speed (the censor matrix).

## Acceptance
- [ ] Two consecutive full labs of the same commit from different checkout paths: the second serves `./lab`'s in-node pass and the host-run packages from the cache, and its default stream time is reported.
- [ ] Every new or changed test mutation-checked, mutations in the Log.
- [ ] lab/README.md says what each cache covers.

## Notes
- Found in TP-284's two full labs of 18bfa3b3 (2026-11-22): run 2 served 29 of the 30 in-node packages, default stream 13m28s.

## Log
- 2026-11-22 created in backlog (from TP-284's review)
- 2026-11-22 backlog → in-progress, owner: agent-tp-285
