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
- 2026-11-22 cause, ./lab: TestFreshLabMarksSayWhat (lab/gotest_test.go) walked the whole checkout, lab/bin included, so the pass's test log listed /src/lab/bin and the run directories under it, which the run's other phases create and fill while ./lab's in-node pass runs (shown with ./lab's test binary's -test.testlogfile with a lab/bin present: open lab/bin, lab/bin/run-*, lab/bin/run-*/tests; after the fix the whole binary's log names no path under the checkout's lab/bin). No test of ./lab uses a binary there through /src, so skipping it drops nothing the pass depends on
- 2026-11-22 fix, ./lab: the walk (now freshLabMarks) skips lab/bin as TestOnlyTheNodesUseTheDeadEndNameserver's does; TestFreshLabMarksSkipTheRunBinaries checks it on a temp checkout; lab/doc.go and README "Cached passes" say a test walking the checkout stays out of lab/bin
- 2026-11-22 cause, host run: go test's cache keys a test on its binary's build ID, which holds the package's directory without -trimpath. With -trimpath, CGO_ENABLED=0, the 16 host-run packages from two checkouts of the same commit: the second served 12 of 16 from go's cache; internal/devmap, internal/dataplane/path, internal/lists and internal/netmap still ran: their tests open paths in the checkout (testdata, sources, a fuzz test's testdata/fuzz seed corpus even when missing), which go test hashes by absolute name and mtime, not content, so they can't hit from another checkout; left as they are (README "What each cache covers"). The same checkout served all 16. No host-run package's tests use runtime.Caller or file paths from the build (one goroutine-leak dump uses runtime.Stack: stack trace names only)
- 2026-11-22 fix, host run: lab/gotesthost.go hostGoTestCommand passes -trimpath; TestGoTestOnHostCachesAcrossCheckouts (lab/gotesthost_test.go) runs GoTestOnHost on a fresh test from two directories (the second cached) and a changed test from a third (not cached); TestHostGoTestCommand's args include it; README "Packages that need no node" and lab/doc.go updated, "What each cache covers" added
- 2026-11-22 mutations, each caught (targeted go test on the Mac, restored after): freshLabMarks without the lab/bin skip (TestFreshLabMarksSkipTheRunBinaries: "marks found [lab/bin/run-x/tests/freshlab_test.go pkg/freshlab_test.go]"); -trimpath dropped from hostGoTestCommand (TestGoTestOnHostCachesAcrossCheckouts: "the same sources from another checkout ran again"; TestHostGoTestCommand: args)
- 2026-11-22 make lint, make test green at c2b84954
- 2026-11-22 filed TP-286 (labctl tests fail on macOS: TestGotestSkipAndTimes, TestGotestRunsNodelessPackagesOnTheHost, temp dir through the /var symlink; reproduced on rewrite b7beec15)
