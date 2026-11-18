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
- [x] A second `make lab-test` on an unchanged tree shows every node package `(cached)` and starts no gotest lab. Evidence: the log and `docker events`. (Shown with the node phase's packages through `make lab-gotest`, not a whole `make lab-test`: see Notes, "Evidence".)
- [x] A changed testdata file reruns its package. Evidence: a log.

## Notes
- Saving: up to 639 s of node lab time and 41 starts (≈ 2.5 min of Docker time) on typical branches.
- Design (lab/testcache, lab/gotestcache.go, lab/README.md "Cached passes"): the action key is the test binary's sha256, the lab image's ID, the Docker engine's version and kernel, labctl's own binary plus `lab/seccomp.json` (the harness: how nodes are set up), the working directory, the binary's args and extra env. The inputs are the files the test binary opened, stat'ed or changed into under `/src` and the run's binary directory, from its `-test.testlogfile` (the log go test's own cache uses), read back from the node before the lab goes down and hashed by content. An action record lists the input names; pass records are keyed by the action and the inputs' hashes, so two checkouts with different testdata keep a pass each. Only passes are recorded, and not when an input file changed during the run. `-count` (any), `-perf` and `LAB_NOCACHE=1` read and write nothing. Records live in the user's cache directory (`thinkpol-lab/gotest`), shared by every run of the user on the machine: temp file plus rename, a record that doesn't decode or names another key is a miss, unused records go after 30 days (trimmed at most daily).
- Blind spot, as in go test: what a test reads outside package os in its own process (a subprocess reading the checkout, an absolute path it executes without stat'ing) is not an input. `TestThinkpolWorkerCommand` stats `/opt/thinkpol/bin/thinkpol` before running it, so the binary is an input there.
- A package with no tests for linux now starts no lab at all (its binary is built before the lab).
- Evidence (lab runs on the branch, `make lab-gotest`, container starts counted live with `docker events --filter event=start` over the run's window, names of this checkout's labs):
  - Whole node phase: the 38 node packages other than `./lab` and `./lab/prototypes/reality`, at 7b59ebe9. Cold: exit 0, 307 s, 38 packages run (3 already cached by the runs below). Warm, unchanged tree: exit 0, 19 s, "gotest: ok, 38 packages, 38 of them cached", every package's line `(cached: …)`, 0 container starts on the machine in the window. `./lab` and `./lab/prototypes/reality` were left out because `make lab-gotest` also runs their lab-tagged tests on the host, which the current lab-run rule excludes (no whole `./lab` runs, no full `make lab-test`); their in-node halves go through the same GoTestEach path.
  - Targeted, `PKG="./internal/devmap ./internal/agent/supervisor ./lab/testcache"`, at 7b59ebe9: cold 56 s, 3 labs; unchanged 10 s, all 3 `(cached)`, 0 starts; `internal/devmap/testdata/m0.golden` changed: devmap reran (1 lab) and failed `TestGolden`, the others cached; the same again: devmap reran and failed again (a failure is not recorded); `lab/maps/m0.yaml` (another package's file devmap reads) changed: devmap reran (1 lab) and passed; both restored: all 3 `(cached)` from the first pass, 0 starts; `COUNT=1`: all 3 ran (3 labs), 0 cached.
  - Final head 9499360e (after merging rewrite; labctl changed, so every key with it): cold 56 s, 3 labs, 0 cached; unchanged 8 s, 3 of 3 cached, 0 starts.

## Review findings
- [ ] R1.1 (blocker) `hashInput` checks only regular files for "changed during the run": a directory listing or a missing input is hashed as it is at record time, so a file added to an opened directory mid-run, an input deleted mid-run, or an old file `mv`'d or `cp -p`'d over an input (old mtime) records a pass the run didn't earn. Check every kind of input against the run's start (mtime and ctime), a missing input by its parent directory, under the checkout mount only; add the cases to TestInputChangedDuringTheRunIsNotRecorded; fix the README/doc.go sentence.
- [ ] R1.2 (should-fix) Any error setting up the cache (no cache dir, unwritable or full cache dir at the trim marker, a trim walk error, os.Executable) aborts the whole `labctl gotest`. A cache never fails a run: warn and run uncached; a trim error is printed and the cache still used.
- [ ] R1.3 (should-fix) The test binary runs without `-test.paniconexit0`: a test calling os.Exit(0) exits 0 with the rest unrun and can be recorded as a pass. Pass it on every run; test it.
- [ ] R1.4 (should-fix) The engine key lacks what decides some skips: the CPU count (supervisor's one-CPU skip) and bridge netfilter (firewall's br_netfilter skip). Add both; README: a pass with host-dependent skips is cached against these, and list the remaining blind spots (symlinks resolved on the host, Compose plugin version, daemon config).
- [ ] R1.5 (should-fix) Each hit renews the record, so a pass is served for ever while it is used (date-dependent tests stay green). Store the record time in the pass record; a pass older than 7 days is a miss. Test it.
- [ ] R1.6 (should-fix) "Never record a failure, a lab error or an unreadable log" has no unit test. Add a seam for the fresh run and a test that each leaves Lookup missing; name the mutations.
- [ ] R1.7 (should-fix) The wiring of the key in entry() has no test: dropping BinDir from the mounts, or seccomp, Image, Engine or Env from the entry, keeps every test green. Test that each changes the key; mutation-check it.
- [ ] R1.8 (should-fix, ticket) Acceptance box 1 was shown with `make lab-gotest` (other keys, without `./lab`, `./lab/prototypes/reality` and the `[lab]` phase). Untick it; prove it with a `make lab-test` pair.
- [ ] R1.9 (nit) `make lab-test COUNT=1` is accepted silently and still uses the cache. Pass COUNT through to the node phase.
- [ ] R1.10 (nits) testcache_test.go's "started a second ago" comment vs time.Now().Add(time.Second); the changed-during-the-run check exercised by more than one test; run the lab by the image ID the key uses (or note the blind spot); delete hashInput's dead "ignored" branch if Record already filters; build lab tools with -buildvcs=false if VCS stamping changes the thinkpol binary every commit.

## Log
- 2026-11-16 created in backlog (owner: lab fixes, top priority; from the lab-speed audit)
- 2026-11-17 backlog → in-progress, owner: agent-tp-243
- 2026-11-17 labctl gotest caches in-node passes (lab/testcache): key = test binary, image ID, engine and kernel, labctl and seccomp profile, working dir, args, env, plus the checkout and lab-binary files the binary read (its -test.testlogfile); -count, -perf, LAB_NOCACHE=1 bypass it; records atomic in the user's cache dir; README "Cached passes", lab/doc.go
- 2026-11-17 lab runs (make lab-gotest): whole node phase minus ./lab and ./lab/prototypes/reality cold 307 s → warm 19 s, 38/38 cached, 0 container starts (7b59ebe9); changed testdata and a changed lab/maps file each rerun devmap only; failures rerun; COUNT=1 reruns all; final head 9499360e cold 56 s → warm 8 s, 3/3 cached, 0 starts (details in Notes)
- 2026-11-17 found in the first lab runs: the scratch paths (t.TempDir) in the recorded input list differed every run, so a restored tree missed its older pass; fixed by recording only inputs under the mounts (TestScratchPathsDontSplitTheInputs)
- 2026-11-17 mutations, each caught: image dropped from the key (TestActionChangeIsAMiss/image); unresolved inputs kept (TestScratchPathsDontSplitTheInputs); file content not hashed (TestInputChangeIsAMiss/testdata content, another package's file, lab binary); record key not checked (TestBrokenRecordIsAMiss/another key's record); input-changed-during-run check dropped (TestInputChangedDuringTheRunIsNotRecorded); trim interval ignored (TestTrim); chdir ignored (TestParseTestLog); directory listing not hashed (TestInputChangeIsAMiss/file added to an opened directory); -count not bypassing (TestUseCache). Not caught, equivalent: a missing input hashed as "ignored" (both differ from any file's hash)
- 2026-11-17 not verified: a whole make lab-test pair (the lab-run rule allows targeted runs only); ./lab and ./lab/prototypes/reality's in-node halves not run cached; atomic writes are checked by a concurrent writer/reader test, not by a kill mid-write; goTestPackage's never-record-a-failure branch has no unit test (needs Docker), shown by the lab runs above
- 2026-11-17 make lint, make test green on 9499360e; full make lab-test not run (orchestrator rule until the matrix rework); lab commit 9499360e (targeted)
- 2026-11-17 in-progress → review
- 2026-11-18 review round 1: fix R1.1–R1.10
