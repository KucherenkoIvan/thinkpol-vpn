---
id: TP-284
title: "The node phase's cache never hits in a full lab"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-243]
refs: []
owner: ""
branch: ""
---

## Goal
A full `make lab-test` of a commit whose packages already passed in nodes on this machine serves them from the node-phase cache (TP-243), whichever checkout directory the run comes from, so the node phase stops spending the default stream's first minutes on work already done and the default stream fits its 15-minute budget.

## Scope
- Measured 2026-11-22 on a quiet runner: a full lab of b01eeccb took 15m12s on the default stream (exit 3: tests passed, over budget; about 12m54s before that day's merges). The harness phase was cached; the node phase ran in full: 0 of 46 packages cached, and 0 of 40 on the earlier full lab of 12574eb5. Full labs run from a fresh checkout directory each time, so the cache never hits in a full lab.
- The node phase takes 12 labs in the run's first ~4.5 min and delays the `lab` package's first lab to 4m18s; the censor matrix then runs from 7m00s to 14m15s and ends the stream.
- Suspected, not verified: the node test binaries are built without `-trimpath` (`goBuild` from `lab/gotest.go`'s `go test -c`), so the checkout's path, compiled into each binary, changes its sha256, which is part of the key. Find which part of the key really changes first.
- Fix it minimally: the key covers sources, dependencies and build flags, not where the checkout sits. A changed test or dependency still misses.

## Out of scope
- The `lab/` phase's own speed (the censor matrix): its tests always run with `-count=1`.

## Acceptance
- [ ] The cause shown: which part of the key changes between two full labs of the same commit from different checkout paths.
- [ ] A test that the key is the same for the same sources built from two different directories (mutation: the old build → fails).
- [ ] Two consecutive full labs of the same commit from different checkout paths: the second serves every unchanged package from the cache, and its default stream time is reported.
- [ ] lab/README.md says what the key covers.

## Notes
- Found in the orchestrator's full-lab timing of b01eeccb (2026-11-22).

## Log
- 2026-11-22 created in backlog (from the full-lab timing of b01eeccb)
