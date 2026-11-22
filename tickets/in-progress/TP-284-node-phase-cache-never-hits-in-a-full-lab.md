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
owner: "agent-tp-284"
branch: "tp-284-node-cache-across-checkouts"
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
- [x] The cause shown: which part of the key changes between two full labs of the same commit from different checkout paths. Evidence: the test binary's sha256 (Action.TestBinary): `go test -c` without `-trimpath` compiles the checkout's directory in; the two builds' hashes and the unchanged parts in the Log (2026-11-22).
- [x] A test that the key is the same for the same sources built from two different directories (mutation: the old build → fails). Evidence: TestKeyIsTheSameFromAnotherCheckout, mutations in the Log.
- [ ] Two consecutive full labs of the same commit from different checkout paths: the second serves every unchanged package from the cache, and its default stream time is reported.
- [x] lab/README.md says what the key covers. Evidence: "Cached passes": the binary covers the package's code, tests and imports, built with `-trimpath`, so not where the checkout sits.

## Notes
- Found in the orchestrator's full-lab timing of b01eeccb (2026-11-22).

## Log
- 2026-11-22 created in backlog (from the full-lab timing of b01eeccb)
- 2026-11-22 backlog → in-progress, owner: agent-tp-284
- 2026-11-22 cause: the node test binaries were built `go test -c` without `-trimpath`, so each checkout's directory was compiled in and the action key's TestBinary (the binary's sha256) differed for every checkout of the same commit. Shown by building the same commit from two directories (linux/amd64, CGO_ENABLED=0): internal/devmap's test binary 03107fac… vs a1a03b87…, lab's 796d560f… vs 646d48f0…; with `-trimpath` both devmap builds 1b083eec… (and the same from a git worktree, so no VCS stamp); labctl (c34db2eb…) and labdns (e262da48…), already `-trimpath -buildvcs=false`, were the same from both; the other key parts (image ID by the Dockerfile's hash, engine, node working directory, args, env, inputs by node path and content) hold no checkout path
- 2026-11-22 fix: lab/gotest.go buildPackageTests builds with `-trimpath`; TestKeyIsTheSameFromAnotherCheckout (lab/gotestcache_test.go) builds a module's package through buildPackageTests and entry() from two directories, the same key, and a changed test or dependency in a third, another key; README "Cached passes" and lab/doc.go say what the key covers
- 2026-11-22 mutations, each caught (targeted go test on the Mac, restored after): `-trimpath` dropped, the old build (TestKeyIsTheSameFromAnotherCheckout: "the same sources built from another checkout key differently"); the binary's hash left out of the action (…/test changed, …/dependency changed)
