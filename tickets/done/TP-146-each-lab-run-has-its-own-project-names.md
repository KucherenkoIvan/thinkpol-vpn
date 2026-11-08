---
id: TP-146
title: "Lab: each run has its own Compose project names"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: [TP-121]
refs: []
owner: "agent-tp-146"
branch: "tp-146-each-lab-run-has-its-own-project-names"
---

## Goal
Two lab runs from one checkout at once (`make lab-gotest` beside `make lab-test`, two `lab-gotest` of one package, two `lab-test`) never replace or remove each other's labs. Each run's labs carry an identity of that run, and a run's clean-up removes only its own.

## Scope
- Today the names come from the checkout alone: `CheckoutProject` (lab/project.go), then `GoTestProject(checkout)+"-"+shortHash(pkg.ImportPath)` for a node-phase lab (`GoTestEach`, lab/gotest.go) and `testProject` for a test's lab. Two runs that start the same package or test pick the same project, and the second `Up` replaces the first's lab mid-test.
- The end of `make lab-test` runs `labctl down -tests` (`DownCheckout(root, true)`, lab/teardown.go), which removes every test and gotest lab of the checkout, so it also removes labs another run is still using.
- Add a per-run identity (e.g. a short run id, or the TP-121 run directory's name) to test and gotest project names, record it on the lab (label or name), and have `down -tests` at the end of `make lab-test` remove only that run's labs. `labctl down` without flags still removes everything the checkout started; `down -stale` is unchanged.
- Keep `THINKPOL_LAB_PROJECT` working, and keep a `THINKPOL_LAB_KEEP` lab findable by `labctl down` (TP-121's `.kept` lists projects).
- Update lab/README.md "Gotchas" (the TP-121 entry on shared project names and the `THINKPOL_LAB_PROJECT` workaround) and lab/doc.go.

## Out of scope
- Binaries: TP-121 gave each run its own.
- Runs from different checkouts: their names already differ by the checkout's hash.

## Acceptance
- [x] `make lab-gotest PKG=<a package in lab-test's node phase>` started during `make lab-test` from the same checkout: both pass, and neither run's clean-up removes the other's labs
- [x] two `make lab-gotest` of one package started together from one checkout both pass
- [x] `labctl down` still removes every lab of the checkout, kept ones included
- [x] lab/README.md Gotchas no longer says to set `THINKPOL_LAB_PROJECT` for a second run
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- Follow-up to TP-121 review finding R1.10 (paranoid 3): TP-121 documented the collision as out of scope, and its round-2 reviewer (torvalds) asked for this ticket.
- Compose project names have a length limit and `overridePattern` caps the override at 40 characters; check that the longest name (override, `-gotest-`, run id, hash) still fits.

## Review findings
- [x] R1.1 (should-fix) `labctl down -run ""` (an unset `$THINKPOL_LAB_RUN`) becomes a plain `labctl down` and removes every lab of the checkout: a given -run is validated, an empty or invalid id is an error; unit test
- [x] R1.2 (should-fix) no unit test pins `DownRun` (a mutant dropping `removeStaleBinaries` passes): fakeDocker test of DownRun (this run's lab and ended binaries only, not run r12's or the checkout's) and DownCheckout(root, false) on the same fixture (removes all three; settles acceptance box 3)
- [x] R1.3 (should-fix) docs/design/api-overview.md "Lab variables" lacks `THINKPOL_LAB_RUN`; lab/README.md should say not to export it
- [x] R1.4 (should-fix, minimal) labs a killed run leaked are no longer removed by the next `make lab-test`: lab/README.md says to run `make lab-down` after an interrupted run
- [x] R1.5 (nit) stale comments: harness_test.go (TestLongestProjectNameStarts, TestLongestProjectNames' claim), bindir_lab_test.go override reason, lab.go and bindir_test.go still describing `down -tests` at the end of lab-test
- [x] R2.1 (should-fix) `labctl down r1 -run r1` or `labctl down r1` stops flag parsing at the positional argument, so runGiven stays false and DownCheckout removes every lab of the checkout: `labctl down` rejects positional arguments with a usage error; unit test before any Docker call
- [x] R2.2 (should-fix, test gap) TestDownRunRemovesItsRunsLabAndBinaries has no lab of the same project name under another root, so a DownRun without its labRoot == root filter passes: add one and assert DownRun leaves it
- [x] R2.3 (nit, test oracle) the fixture ticks acceptance box 3 without a kept lab, and the stateless fake docker never shows compose down was asked: add a kept lab (in the run directory's .kept) and assert through the fake's recorded calls that compose down ran for each project DownCheckout reports removed, and that DownRun asked for no others

## Log
- 2026-10-29 created in backlog (TP-121 R1.10 follow-up)
- 2026-11-07 backlog → in-progress, owner: agent-tp-146
- 2026-11-07 finisher: branch has the change (72ec24f: run id THINKPOL_LAB_RUN in test and gotest project names, labctl run-id, make lab-test's clean-up is labctl down -run; README Gotchas no longer says to set THINKPOL_LAB_PROJECT; tests TestRunProjectNames, TestLongestProjectNames, TestRunIDs, lab TestDownRunRemovesOnlyItsRun)
- 2026-11-07 finisher: merged rewrite 7852af8 (head c66ccc8) in as 7c4984a; make lint green, make test green
- 2026-11-07 finisher: full make lab-test passed on 7c4984a (LAB_P=4, run alone): lab/ packages ok (TestDownRunRemovesOnlyItsRun included), gotest ok for 36 packages
- 2026-11-07 finisher: two make lab-gotest PKG=./internal/dataplane/netcfg/... started 2 s apart from this checkout overlapped for about a minute; both passed (47 tests each)
- 2026-11-07 finisher: a second full make lab-test on 7c4984a with make lab-gotest PKG=./internal/dataplane/netcfg/... COUNT=3 started 450 s in: both passed (lab-gotest 141 passes); the lab-gotest ran through lab-test's last half minute, its clean-up included (the two ended within seconds); TestDownRunRemovesOnlyItsRun shows the clean-up leaving another run's running lab
- 2026-11-07 finisher: `labctl down` box left open: not run, since make lab-down here would also remove an earlier run's leftover gotest lab of this checkout that the finisher didn't create; DownCheckout is unchanged by the branch
- 2026-11-07 in-progress → review
- 2026-11-07 review → has-errors (round 1 findings R1.x)
- 2026-11-07 fix round 1: R1.1 labctl down tracks -run with fs.Visit, so a given -run always goes to DownRun, which rejects an empty or invalid id before asking Docker (lab/labctl/main_test.go TestDownRunRejectsABadIDBeforeDocker; mutation "case *run != \"\"" instead of runGiven: fails, the fake docker is called)
- 2026-11-07 fix round 1: R1.2 TestDownRunRemovesItsRunsLabAndBinaries (lab/bindir_test.go, fakeDocker): DownRun(root, "r1") removes only run r1's lab and the ended run directory, not run r12's or the checkout's; DownCheckout(root, false) removes all three (ticks acceptance box 3). Mutations: DownRun without removeStaleBinaries fails; startedByRun's gotest match without the trailing "-" fails (r12 removed); DownCheckout always tests-only fails
- 2026-11-07 fix round 1: R1.3 THINKPOL_LAB_RUN row in docs/design/api-overview.md "Lab variables"; lab/README.md Environment says not to export it. R1.4 lab/README.md Gotchas: make lab-down after an interrupted run. R1.5 stale comments fixed (harness_test.go, bindir_lab_test.go, lab.go, bindir_test.go)
- 2026-11-07 fix round 1: make lint and make test green
- 2026-11-07 fix round 1 (continued after a stop): checked f8af0d8 against the round's findings; re-ran mutations "case *run != \"\"" (TestDownRunRejectsABadIDBeforeDocker fails) and DownRun without removeStaleBinaries (TestDownRunRemovesItsRunsLabAndBinaries fails)
- 2026-11-07 fix round 1: merged rewrite b1930a9 as a65939e; make lint and make test green; make lab-down removed the stopped run's two leftover labs of this checkout
- 2026-11-07 fix round 1: a full make lab-test on a65939e failed at load ~61 (seven agents compiling): supervisor TestASourceFloodStallsNoOtherSpace (calm median 485 ms), path TestAsymmetricRoutesDeliverBothWays/stream (no path to the peer), lab package 20 m timeout in TestBlobDistribution/TestCensorMatrix; timing under load, none of it in code this branch touches
- 2026-11-07 fix round 1: re-run of the full make lab-test on a65939e under the exclusive CPU lock (LAB_P=4) passed: lab/ packages ok, gotest ok for 37 packages
- 2026-11-07 has-errors → review
- 2026-11-07 review → has-errors (round 2 findings R2.x)
- 2026-11-07 fix round 2: R2.1 labctl down rejects positional arguments with a usage error before asking Docker (lab/labctl/main.go; lab/labctl/main_test.go TestDownRejectsPositionalArgumentsBeforeDocker: down r1, down r1 -run r1, down -tests r1). Mutation: the fs.NArg() check disabled: fails
- 2026-11-07 fix round 2: R2.2 and R2.3 TestDownRunRemovesItsRunsLabAndBinaries (lab/bindir_test.go) adds a lab named as run r1's under another checkout's root and a kept lab of run r2 listed in an ended run directory's .kept; the fake docker records its calls and the test checks the projects compose down was asked for: DownRun only r1's lab (the kept lab's directory stays while it is up), DownCheckout every lab of the checkout, the kept one included, never the other checkout's. Mutations: DownRun without labRoot == root: fails (other checkout's lab removed); compose ps instead of compose down in downProject: fails; DownCheckout skipping run r2's labs: fails
- 2026-11-07 fix round 2: make lint and make test green on 765840a's tree; no make lab-test this round (labctl argument checking and unit tests only, per the round's brief); rewrite unchanged at b1930a9
- 2026-11-07 has-errors → review
- 2026-11-07 review → done, merged into rewrite (round 1: go-paranoid, go-style, pocket-torvalds; round 2 from the delta check, read by the orchestrator; full lab last passed on a65939e)
