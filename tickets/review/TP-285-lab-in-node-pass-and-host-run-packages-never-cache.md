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
- [x] Two consecutive full labs of the same commit from different checkout paths: the second serves `./lab`'s in-node pass and the host-run packages from the cache, and its default stream time is reported. Evidence: the two full labs of bf05ff02 in the Log: run 2 served all 30 in-node packages (`./lab` included, no node lab started) and 12 of the 16 host-run packages; default stream 12m26s. The other 4 host-run packages open paths in the checkout, which go test's cache keys by absolute name and mtime, so they can't hit from another checkout (Log, README "What each cache covers").
- [x] Every new or changed test mutation-checked, mutations in the Log. Evidence: TestFreshLabMarksSkipTheRunBinaries, TestGoTestOnHostCachesAcrossCheckouts, TestHostGoTestCommand; mutations in the Log (2026-11-22).
- [x] lab/README.md says what each cache covers. Evidence: "What each cache covers" (after "Cached passes"): labctl's passes for node runs, go test's own cache for the host run (what its key holds, which packages it can't serve from another checkout), the harness stamp; "Cached passes" says a test walking the checkout skips lab/bin.

## Notes
- Found in TP-284's two full labs of 18bfa3b3 (2026-11-22): run 2 served 29 of the 30 in-node packages, default stream 13m28s.

## Log
- 2026-11-22 created in backlog (from TP-284's review)
- 2026-11-22 backlog → in-progress, owner: agent-tp-285
- 2026-11-22 cause, ./lab: TestFreshLabMarksSayWhat (lab/gotest_test.go) walked the whole checkout, lab/bin included, so the pass's test log listed /src/lab/bin and the run directories under it, which the run's other phases create and fill while ./lab's in-node pass runs (shown with ./lab's test binary's -test.testlogfile with a lab/bin present: open lab/bin, lab/bin/run-*, lab/bin/run-*/tests; after the fix the whole binary's log names no path under the checkout's lab/bin). No test of ./lab uses a binary there through /src, so skipping it drops nothing the pass depends on
- 2026-11-22 fix, ./lab: the walk (now freshLabMarks) skips lab/bin as TestOnlyTheNodesUseTheDeadEndNameserver's does; TestFreshLabMarksSkipTheRunBinaries checks it on a temp checkout; lab/doc.go and README "Cached passes" say a test walking the checkout stays out of lab/bin
- 2026-11-22 cause, host run: go test's cache keys a test on its binary's build ID, which holds the package's directory without -trimpath. With -trimpath, CGO_ENABLED=0, the 16 host-run packages from two checkouts of the same commit: the second served 12 of 16 from go's cache; internal/devmap, internal/dataplane/path, internal/lists and internal/netmap still ran: their tests open paths in the checkout (testdata, sources, a fuzz test's testdata/fuzz seed corpus even when missing), which go test hashes by absolute name and mtime, not content, so they can't hit from another checkout; left as they are (README "What each cache covers"). The same checkout served all 16. No host-run package's tests use runtime.Caller or file paths from the build (one goroutine-leak dump uses runtime.Stack: stack trace names only)
- 2026-11-22 fix, host run: lab/gotesthost.go hostGoTestCommand passes -trimpath; TestGoTestOnHostCachesAcrossCheckouts (lab/gotesthost_test.go) runs GoTestOnHost on a fresh test from two directories (the second cached) and a changed test from a third (not cached); TestHostGoTestCommand's args include it; README "Packages that need no node" and lab/doc.go updated, "What each cache covers" added
- 2026-11-22 mutations, each caught (targeted go test on the Mac, restored after): freshLabMarks without the lab/bin skip (TestFreshLabMarksSkipTheRunBinaries: "marks found [lab/bin/run-x/tests/freshlab_test.go pkg/freshlab_test.go]"); -trimpath dropped from hostGoTestCommand (TestGoTestOnHostCachesAcrossCheckouts: "the same sources from another checkout ran again"; TestHostGoTestCommand: args)
- 2026-11-22 make lint, make test green at c2b84954
- 2026-11-22 filed TP-286 (labctl tests fail on macOS: TestGotestSkipAndTimes, TestGotestRunsNodelessPackagesOnTheHost, temp dir through the /var symlink; reproduced on rewrite b7beec15)
- 2026-11-22 two full make lab-test runs of bf05ff02, back to back on a quiet runner (no other lab containers), each from a fresh checkout at its own path: run 1 (cold: labctl changed, so every node key is new) exit 3 (passed, over budget; NOT JUDGED: reality / active prober), default stream 16m23s, long 4m29s, node phase 0 of 46 cached (in-node 0 of 30, ./lab's pass 2m18s and recorded: no "pass not recorded" line; host-run 0 of 16), 12 node labs; run 2 exit 0 (NOT JUDGED: reality / active prober), default stream 12m26s, long 3m5s, node phase "46 packages, 42 of them cached": in-node 30 of 30 (./lab included), no node lab started; host-run 12 of 16 (ran: internal/devmap 0.6s, internal/lists 2.5s, internal/dataplane/path 21.8s, internal/netmap 31.5s)
- 2026-11-22 not verified / left open: the 4 host-run packages whose tests open checkout paths still run from a fresh checkout (go test's cache keys those by absolute name and mtime; making them hit would mean labctl caching the host run itself or the tests not opening checkout paths; out of scope); make lint, make test ran at c2b84954, the code of bf05ff02 (only a board-only merge and this ticket since)
- 2026-11-22 lab commit bf05ff02 (the two full labs above)
- 2026-11-22 in-progress → review
- 2026-11-22 review nits: TestFreshLabMarksSkipTheRunBinaries (lab/gotest_test.go) asserts the fixture's mark (no comment) reports a problem; TestGoTestOnHostCachesAcrossCheckouts (lab/gotesthost_test.go) adds a fourth checkout whose dependency in the module changed so the unchanged test fails: it runs and fails, not a cached pass (a constant or an inlined dead branch changed in the dependency leaves the test binary identical, and go then serves it from the cache, rightly: the key is the binary's content)
- 2026-11-22 mutations, each caught (targeted go test on the Mac, restored after): freshLabMarks recording freshLabMark{rel, ""} (TestFreshLabMarksSkipTheRunBinaries: "no problem reported for a mark without a comment"); the fourth checkout given the unchanged dependency (TestGoTestOnHostCachesAcrossCheckouts: "want it run and failed", got cached pass). No labctl code decides a dependency's staleness (go's cache does), so no code mutation applies to the dependency case
- 2026-11-22 make lint, make test green at 2f2ef5d8; the two tests' packages (TestFreshLabMarks*, TestGoTestOnHost*, TestHostGoTest*) green on the Mac too; no lab run for the nits (test-only change in ./lab's unit tests)
