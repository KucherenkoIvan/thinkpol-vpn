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
- [x] Two consecutive full labs of the same commit from different checkout paths: the second caches every unchanged in-node package except ./lab: 29 of 30; default stream 13m28s. Evidence: the two full labs of 18bfa3b3 in the Log (cold run: 0 of 46 cached; second run exit 0, 29 of the 30 in-node packages cached); ./lab and the host-run packages are TP-285.
- [x] lab/README.md says what the key covers. Evidence: "Cached passes": the binary covers the package's code, tests and imports, built with `-trimpath`, so not where the checkout sits.

## Notes
- Found in the orchestrator's full-lab timing of b01eeccb (2026-11-22).
- Evidence, two full `make lab-test` runs of 18bfa3b3, back to back on a quiet runner (no other lab containers), each from a fresh checkout at its own path; offsets from each run's start:
  - Run 1 (cold: no record for the new binaries): exit 2 (tests passed, over budget; NOT JUDGED: reality / active prober), default stream 16m38s, long 4m37s; node phase "gotest: ok, 46 packages, 0 of them cached", 14 node-phase lab starts, the last node lab down at 5m49s; the harness phase ran (lab/ code changed); the first lab-phase lab started at 0m38s; the censor matrix's labs from 1m47s to 10m48s.
  - Run 2: exit 0, default stream 13m28s of its 15m budget, long 3m13s; node phase "gotest: ok, 46 packages, 29 of them cached", 1 node-phase lab start (`./lab`, 40 s), the last node lab down at 1m14s; the harness phase cached; the first lab-phase lab started at 0m40s; the censor matrix's labs from 0m51s to 10m46s.
- Still run in a second full lab (out of scope here, not this key's checkout path; follow-up TP-285):
  - `./lab`'s in-node pass is never recorded in a full lab, from any checkout: "pass not recorded: testcache: an input changed during the run: <checkout>/lab/bin" in both runs. One of its tests reads the checkout's `lab/bin`, which the run's own phases write meanwhile. 40 s of node time, off the default stream's critical path now.
  - The 16 packages that need no node run on the host under go test's own cache, which keys on the checkout's path (the package directory in its build IDs without `-trimpath`, and the absolute names of the files a test opens), so they all ran (the longest 20 s, all in the first minute).

## Log
- 2026-11-22 created in backlog (from the full-lab timing of b01eeccb)
- 2026-11-22 backlog → in-progress, owner: agent-tp-284
- 2026-11-22 cause: the node test binaries were built `go test -c` without `-trimpath`, so each checkout's directory was compiled in and the action key's TestBinary (the binary's sha256) differed for every checkout of the same commit. Shown by building the same commit from two directories (linux/amd64, CGO_ENABLED=0): internal/devmap's test binary 03107fac… vs a1a03b87…, lab's 796d560f… vs 646d48f0…; with `-trimpath` both devmap builds 1b083eec… (and the same from a git worktree, so no VCS stamp); labctl (c34db2eb…) and labdns (e262da48…), already `-trimpath -buildvcs=false`, were the same from both; the other key parts (image ID by the Dockerfile's hash, engine, node working directory, args, env, inputs by node path and content) hold no checkout path
- 2026-11-22 fix: lab/gotest.go buildPackageTests builds with `-trimpath`; TestKeyIsTheSameFromAnotherCheckout (lab/gotestcache_test.go) builds a module's package through buildPackageTests and entry() from two directories, the same key, and a changed test or dependency in a third, another key; README "Cached passes" and lab/doc.go say what the key covers
- 2026-11-22 mutations, each caught (targeted go test on the Mac, restored after): `-trimpath` dropped, the old build (TestKeyIsTheSameFromAnotherCheckout: "the same sources built from another checkout key differently"); the binary's hash left out of the action (…/test changed, …/dependency changed)
- 2026-11-22 make lint, make test green at 18bfa3b3
- 2026-11-22 two full make lab-test runs of 18bfa3b3 from two fresh checkouts at different paths, back to back, quiet runner: run 1 exit 2 (passed, over budget), default 16m38s, long 4m37s, node 0 of 46 cached, 14 node labs; run 2 exit 0, default 13m28s, long 3m13s, node 29 of 46 cached (29 of the 30 in-node packages), 1 node lab (details in Notes)
- 2026-11-22 not verified / left open: box 3 not ticked: ./lab never records its in-node pass in a full lab (its input lab/bin changes during the run), and the 16 host-run packages miss go test's own cache from another checkout; both out of scope, for the orchestrator (Notes)
- 2026-11-22 lab commit 18bfa3b3 (the two full labs above)
- 2026-11-22 in-progress → review
- 2026-11-22 review nits: lab/README.md no longer says the host-run `go test` builds as a node's run does (the node build has `-trimpath`, the host's doesn't); README "Cached passes" notes node test stack traces name files by module path; box 3 reworded to what was proven (orchestrator) and ticked; follow-up filed as TP-285
- 2026-11-22 make lint, make test green at b5c8ba3a (docs and ticket only since the two full labs; no lab run)
- 2026-11-22 review → done (merged into rewrite)
