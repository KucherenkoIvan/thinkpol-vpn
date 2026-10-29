---
id: TP-121
title: "Lab: two runs from one checkout don't rebuild each other's binaries"
milestone: M2
area: tests
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-claude-tp121"
branch: "tp-121-lab-runs-from-one-checkout-share-binaries"
---

## Goal
Two lab runs from the same checkout at the same time (two `make lab-gotest`, or `lab-gotest` beside `lab-test`) each run the binaries they built.

## Scope
- Today every run builds into the one `lab/bin` of the checkout: the test binaries at `lab/bin/tests/<pkg>.test` (`lab/gotest.go`, `goTest`) and `thinkpol`, `labdns`, `censord` (`lab/prepare.go`). A second run rebuilds a file a running container has open or is about to exec, and the first run fails with errors like `fork/exec /proc/self/exe: no such file`.
- Give each run its own binary directory (per lab, or per process), mounted where `BinDir` points in the container, and remove it when the lab is torn down. Keep `make lab-test`'s single run as fast as today: no extra builds when only one run is going.
- A lab test that builds while another run uses the same checkout passes.

## Acceptance
- [x] two `make lab-gotest` runs of different packages started together from one checkout both pass
- [x] no `lab/bin` directories are left behind after either run ends (passed, failed or interrupted)
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- Seen during TP-120 (2026-10-21) when two reviewers ran lab tests from one worktree.
- **Slot (pre-M2 phase, 2026-10-24).** Wave 0, first in the phase.

## Review findings
Round 1 (paranoid, torvalds, go-style, auto second opinion, 2026-10-28): the flock-and-sweep core holds; a kept lab loses its binaries, Main's signal handler does harm, and the API surface is wider than it needs to be.
- [x] R1.1 a `THINKPOL_LAB_KEEP` lab loses its binaries: `Main` removes the run directory it mounts, and the next run's sweep would too; pin it with a kept marker that only `labctl down` sweeps (paranoid 1, torvalds 1)
- [x] R1.2 drop `Main`'s signal handler (it hangs behind `preparedMu` during builds and swallows a second Ctrl-C); `Main` returns instead of calling `os.Exit`, interrupted runs are left to the sweep; restate "interrupted" (and "failed" for a `-timeout` panic) in the Log (paranoid 2, 7, torvalds 2, auto)
- [x] R1.3 a lab package without `lab.Main` in its TestMain leaks its run directory silently; fail loudly in `start` (torvalds 3, auto)
- [x] R1.4 unexported or unused exports: delete `Prepare`, unexport `RemoveStaleBinaries` (torvalds 5, 6, go-style 3)
- [x] R1.5 no `standalone bool` in `up`: callers pass how the binaries are made; one clean-up path on error; rename `UpStandalone` to `UpDetached` (torvalds 7)
- [x] R1.6 the `runDir` type clashes with `Lab.runDir` and the local in `up`; rename it after what it holds (torvalds 8, go-style 2)
- [x] R1.7 the mechanism comment belongs in lab/doc.go, which still says nothing is shared (go-style 1)
- [x] R1.8 `RemoveRunBinaries(ctx)` without a root (removes whatever this process holds; no `Root()` lookup at exit); labctl defers it only in gotest; don't forget an entry whose removal failed (torvalds 4, auto)
- [x] R1.9 test binaries within one process are rebuilt over a file a parallel lab runs; build each package's tests once per process (torvalds 9)
- [x] R1.10 `lab-gotest` beside `lab-test` (or two `lab-gotest` of one package) collide on Compose project names, and `lab-test`'s final `down -tests` removes the other run's gotest labs: fix if small, else document precisely in README and the Log as out of scope (paranoid 3)
- [x] R1.11 delete the legacy sweep (pre-TP-121 `lab/bin` entries) (torvalds 10, paranoid 8)
- [x] R1.12 unit tests leave a `bin-<hash>.lock` in TMPDIR on every `make test` (paranoid 9, go-style)
- [x] R1.13 no test catches dropping the creation lock (`lockBinRoot` in `newRunDir`) (paranoid 5)
- [x] R1.14 stale comments: lab/Dockerfile:2 "into lab/bin", the unwrapped renderCompose line (paranoid 10, torvalds 12, go-style 5)
- [x] R1.15 README wording: the end of `make lab-test` skips the sweep with `THINKPOL_LAB_KEEP`; "Leftovers" omits binaries (go-style 9)
- [x] R1.16 tests use `os.IsNotExist`; use `errors.Is(err, fs.ErrNotExist)` (go-style 6)
- [x] R1.17 bare filesystem errors from `newRunDir` lack the `lab:` prefix (go-style 7)
- [x] R1.18 `Up`'s doc comment runs two paragraphs together (go-style 4)
- [x] R1.19 labctl usage overstates `-stale`: it removes no binaries (go-style 8, auto)
- [x] R1.20 bindir_lab_test.go copies the sweep's liveness check; share one helper (torvalds 13)

Round 2 (paranoid, torvalds, 2026-10-28): the R1 fixes hold, but labctl down's sweep still takes a kept lab's binaries while the lab is up; `Up` skips R1.3's check, and the build cache keeps failures.
- [x] R2.1 labctl down's sweep removes kept directories whose labs are still up (another `THINKPOL_LAB_PROJECT`, Docker failing partway, two spellings of one checkout): record each kept lab's project in `.kept`, remove a kept directory only when none of its projects is up; test `DownCheckout`'s sweep with two kept projects, one still up (paranoid 1, torvalds S1)
- [x] R2.2 a `-timeout` hang with `THINKPOL_LAB_KEEP` leaves no `.kept`: mark at creation when KEEP is set, unmark in `remove` if no lab was kept (paranoid 2)
- [x] R2.3 the exported `Up` skips R1.3's Main check: delete it, callers use `up(…, processBinaries)` (torvalds S2)
- [x] R2.4 `buildTestsOnce` caches a failed build for the process: cache successes only, with a test (paranoid 4, torvalds S3)
- [x] R2.5 a failed removal stays cached, unlocked and half-deleted: forget the entry anyway and leave the directory to the sweep; fix the doc; R1.8's last clause changes (paranoid 3, torvalds S4)
- [x] R2.6 lab/doc.go still says nothing is shared between tests, "the test binaries GoTest runs once" misparses, and the doc/README "together with the lab" line is false (torvalds S5, paranoid 1)
- [x] R2.7 no real `THINKPOL_LAB_KEEP` run: one manual run of a failing throwaway lab test, `.kept` and binaries survive, `make lab-down` removes both; logged (torvalds S6)
- [x] R2.8 no test fails when `cleanup` drops `keepBinaries` or `DownCheckout` drops its sweep, or when a failed removal's entry is kept (paranoid 5, torvalds S6)
- [x] R2.9 R1.17 partial: errors from `tryLockMode`, `RemoveAll`, `removeIfEmpty`, `runDirLive` lack the `lab:` prefix (paranoid 6)
- [x] R2.10 one unremovable leftover fails every lab start: make the run's own sweep best-effort (paranoid 7)
- [x] R2.11 naming: one word for run/process binaries (`runDirPrefix`, `runDirLive` vs `Lab.runDir`), and `binaries` → `labInputs` since it also builds the image (torvalds N1, N2)
- [x] R2.12 the `if err == nil` cascade in `up` (torvalds N3)
- [x] R2.13 goBuild's dead "a package that lost its tests" branch (torvalds N4)
- [x] R2.14 `fatalTB` depends on `start` calling `Name` before `up`: say so (torvalds N5)
- [x] R2.15 the kept-marker check is written three times: one `keptBy` helper (torvalds N6)
- R1.10 follow-up (per-run project identity in names and `down -tests`): TP-146 (torvalds); not in this ticket.

Round 3 (2026-10-29, paranoid, torvalds): the R2 fixes hold; labctl down still asks Docker before it checks which runs are alive, and "kept" has two sources of truth.
- [x] R3.1 labctl down asks Docker which labs are up before it takes the lab/bin lock and checks which runs are alive: a run that dies in that gap, its lab brought up by an orphaned `docker compose` child, loses its kept lab's binaries; under the lock, collect the ended runs' directories first, then ask Docker; keep a directory while `lab/.run/<project>` exists for a project its `.kept` lists if that holds up, else document the orphaned-compose gap as accepted (paranoid 1)
- [x] R3.2 no test for DownCheckout's fallback when Docker can't list labs (keep every kept directory): a fake docker failing the label query; DownCheckout errors, keeps the kept directory, removes an ended unkept one (paranoid 2)
- [x] R3.3 `KeepEnv` is read twice (start's `.kept` line, cleanup's `keep`), two sources of truth for "kept": read it once in start and pass `keep` to cleanup; a kept lab always has its `.kept` line by construction; TestCleanupKeepsAFailedLabsBinaries stops writing `.kept` itself and checks the kept directory survives a later sweep; a test fails when start drops its `recordLab` (paranoid 3, torvalds S2)
- [x] R3.4 start's comment says a lab left up by a `-timeout` panic keeps its binaries, which holds only with `KeepEnv` (torvalds S1)
- [x] R3.5 `GoTestEach`'s doc doesn't say its caller removes the binaries with `RemoveRunBinaries` (torvalds S3)
- [x] R3.6 the R1.10 follow-up's ticket id is missing from the Log and README Gotchas: TP-146 (torvalds S4)
- [x] R3.7 `runBinariesLive` returns the `lock.Close` error without the `lab:` prefix (paranoid 4)
- [x] R3.8 bindir_lab_test.go fails when another run from the checkout dies during it: check only the directories created after it started (paranoid 5)
- [x] R3.9 nits: lab/doc.go's line wrap; start's `prepare` call reads as a second build; DownCheckout's doc is one 60-word sentence (torvalds N1–N3)

Round 4 (2026-10-29): paranoid and torvalds: merge, no blockers; the README and start's comment still state the kept-binaries rule without the accepted orphaned-compose gap; one test gap; nits. Folded in one round, merged without another review.
- [x] R4.1 lab/README.md and start's comment (lab.go) promise a kept lab's binaries stay with no exception: name the accepted orphaned-compose gap in both (torvalds S1, paranoid 5)
- [x] R4.2 sweepBinRoot's comment judges liveness when Docker answers; it is judged at each run's lock check (torvalds N1)
- [x] R4.3 the `labsUp` signature is spelled out twice: a named `labLister` type (torvalds N2)
- [x] R4.4 `startTB` embeds a nil `testing.TB`: a `Cleanup` that records the call and fails the test, and a comment listing the TB methods start may call (torvalds N3, paranoid 4)
- [x] R4.5 no test fails when the sweep drops a failed Docker query's error (DownCheckout's own query fails first): a unit test of removeStaleBinaries with a failing labsUp (paranoid 1)
- [x] R4.6 a short write to `.kept` glues the next project onto the fragment: recordLab writes a leading newline, with a test (paranoid 2)
- [x] R4.7 bindir_lab_test.go's comment doesn't say where the snapshot is taken or that its mutant may survive a concurrent sweep (paranoid 3)

## Log
- 2026-10-22 created in backlog (TP-120 out-of-scope note)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 0)
- 2026-10-28 backlog → in-progress, owner: agent-claude-tp121
- 2026-10-28 done: each lab-starting process builds into its own `lab/bin/run-*` (lab/bindir.go), mounted at BinDir and held by a flock inside it; removed when the run ends (labctl defers `lab.RemoveBinaries`; lab test packages call `lab.Main` from TestMain, which also removes it on SIGINT/SIGTERM), and `lab/bin` goes with the last run. Runs killed outright (SIGKILL, a test binary's -timeout panic) leave an unlocked dir that the next run, `labctl down` and the end of `make lab-test` sweep; the sweep also removes pre-TP-121 leftovers (`thinkpol`, `labdns`, `censord`, `tests`). No extra builds: each process built its own tools before too, only into the shared dir.
- 2026-10-28 ambiguity: picked "per process" over "per lab" (one build per run, as today). `make lab-up`'s lab outlives labctl, so it gets `lab.UpStandalone`: binaries under its own `lab/.run/<project>/bin`, removed with the lab. "Interrupted" means SIGINT/SIGTERM is cleaned up at once; a hard kill is cleaned up by the next run or `make lab-down`.
- 2026-10-28 tests: bindir_test.go (unit, 3 tests; mutations: the sweep ignores live locks, no legacy sweep, the sweep skips dead run dirs, RemoveBinaries keeps the cache entry, remove leaves an empty lab/bin; each fails a test) and bindir_lab_test.go TestAnotherRunFromTheCheckoutBuildsItsOwnBinaries (a second process, labctl gotest of ./lab/ip, runs beside this run's lab; mutations: both runs share one dir → this run's binary disappears; labctl skips RemoveBinaries → "left behind").
- 2026-10-28 verified: two concurrent `make lab-gotest` (./internal/dataplane/netcfg/..., ./lab/censor/...) both passed with both run dirs present at once for 7 s, and lab/bin was gone after; SIGINT to a `make lab-gotest` process group and to a `go test -tags lab` run each left no lab/bin. `make lint`, `make test` green; `make lab-test` LAB_P=4 green on ac7a00e, no lab/bin left.
- 2026-10-28 out of scope: an interrupted `go test -tags lab` still leaks its labs (as before; `labctl down -tests` removes them), and an interrupted `labctl gotest` once left an empty `lab/.run/<project>` (compose.json only) behind, likely because its `docker compose down` got the SIGINT as well.
- 2026-10-28 in-progress → review
- 2026-10-28 review → has-errors (round 1: R1.1–R1.20)
- 2026-10-28 has-errors → in-progress, owner: agent-claude-tp121
- 2026-10-28 round 1 fixed (6ab102a): a kept lab (`THINKPOL_LAB_KEEP`) marks its run directory `.kept`; the run leaves it and only `labctl down`/`down -tests` (after removing the labs) sweeps it (R1.1). `lab.Main` has no signal handler and returns; a lab test whose package lacks it fails in `start` (R1.2, R1.3). `Prepare` deleted, `removeStaleBinaries` unexported, `UpStandalone` → `UpDetached` with `up` taking a `binaries` func and one error clean-up, type `runDir` → `runBinaries` (R1.4–R1.6). Mechanism in lab/doc.go (R1.7). `RemoveRunBinaries(ctx)` removes what the process holds and keeps an entry whose removal failed; labctl defers it in gotest only (R1.8). A package's tests are built once per binary directory (`buildTestsOnce`); goBuild's per-output mutexes went with it (R1.9). Legacy sweep deleted (R1.11). The lab/bin lock is `lab/.run/bin.lock` of the checkout, so unit tests leave nothing in TMPDIR and runs with different TMPDIRs or path spellings share it (R1.12, paranoid 4). Comments, README, errors.Is, `lab:` prefixes, doc paragraph, labctl usage (R1.14–R1.19); bindir_lab_test.go uses `runDirLive` (R1.20).
- 2026-10-28 acceptance restated (R1.2): "interrupted" and a `-timeout` "failed" run are cleaned up by the next run from the checkout, `make lab-down`, or the end of `make lab-test`, not at once; a run that ends normally removes its directory itself.
- 2026-10-28 out of scope (R1.10): `lab-gotest` beside `lab-test` (or two `lab-gotest` of one package, or two `lab-test`) from one checkout still share Compose project names (`<prefix>-gotest-<pkg hash>`, test labs), so one replaces the other's lab mid-test, and `lab-test`'s final `down -tests` removes the other run's labs; fixing it needs a per-run identity in project names and in `down -tests`. Documented in README "Gotchas" with the workaround (`THINKPOL_LAB_PROJECT` for one run). Binaries no longer collide. Follow-up: TP-146.
- 2026-10-28 tests (round 1): bindir_test.go TestAKeptLabsBinariesStayUntilLabctlDown (mutations: remove ignores `.kept`; the sweep ignores `.kept`; labctl down's sweep skips kept dirs), TestRunDirectoriesWaitForTheCheckoutLock (mutations: newRunBinaries without lockBinRoot; remove without it), TestStartWithoutMainFails (mutation: no Main check in start), TestTestBinariesAreBuiltOncePerDirectory (mutation: no sync.Once), and the reworked TestRemoveRunBinariesForgetsTheRun (mutation: the entry kept) and TestRunsHaveTheirOwnBinaryDirectories (mutation: the sweep removes live dirs); each mutation fails its test. The lab test's "labctl skips its removal" check only holds when no other run from the checkout sweeps first (paranoid 6); not re-mutated this round.
- 2026-10-28 verified (round 1): `make lint`, `make test` green; `make lab-test` LAB_P=1 (other labs running) green on 6ab102a, no lab/bin left (only lab/.run/bin.lock). Not verified: a real `THINKPOL_LAB_KEEP` failure kept with its binaries (unit-tested only); the lab test's mutations were not re-run.
- 2026-10-28 in-progress → review
- 2026-10-28 review → has-errors (round 2: R2.1–R2.15)
- 2026-10-28 has-errors → in-progress, owner: agent-claude-tp121
- 2026-10-28 takeover (agent-claude-tp121, after the round-2 fixer died at fede585): re-read fede585 against R2.1–R2.15; finished R2.9 (waitLock's errors now carry `lab: <what>:`, which covers lockBinRoot) and R2.6 (doc.go's "the test binaries GoTest runs into" sentence reworded); added TestALeftoverTheSweepCantRemoveDoesntStopTheNextRun (R2.10); the two unremovable-directory tests skip as root, since a lab node runs the unit tests as root and the read-only mode doesn't stop it.
- 2026-10-28 round 2 fixed (fede585, 630609d, f4dd95c): `.kept` lists every lab a run starts with KEEP, written before the lab starts; a run's own sweep never removes such a directory, and `labctl down` removes it only once none of the projects it lists is up on the daemon (keeps all of them if Docker can't list labs) (R2.1, R2.2, R2.15 `keptBy`). `Up` deleted; callers use `up(…, runInputs)` (R2.3). `buildTestsOnce` caches successes only (R2.4). `RemoveRunBinaries` forgets every entry, removed or not, and leaves a failed one to the sweep: R1.8's "keep an entry whose removal failed" is reversed (R2.5). Docs: lab/doc.go, README, DownCheckout (R2.6). Best-effort sweep in newRunBinaries (R2.10). Names: `runBinariesPrefix`, `runBinariesLive`, `Lab.stateDir`, `labInputs`/`runInputs`/`detachedInputs` (R2.11). `up` without the `if err == nil` cascade (R2.12), goBuild's dead branch gone (R2.13), the `fatalTB` dependency on `start` stated (R2.14).
- 2026-10-28 tests (round 2), each mutation fails its test: TestLabctlDownKeepsTheBinariesOfKeptLabsStillUp (fake `docker` on PATH; mutations: DownCheckout without its sweep; labUp always false; the sweep ignores labUp), TestCleanupKeepsAFailedLabsBinaries (mutation: cleanup without `bins.keep()`), TestRemoveRunBinariesForgetsADirectoryItFailedToRemove (mutation: a failed entry kept), TestAFailedTestBuildIsRetried (mutation: a failed build marked done), TestALeftoverTheSweepCantRemoveDoesntStopTheNextRun (mutation: newRunBinaries fails on a sweep error) (R2.8). `start` recording the lab in `.kept` has no unit test; the manual run below covers it.
- 2026-10-28 verified (R2.7), a throwaway failing lab test (not committed) run with `go test -tags lab` as `make lab-test` runs it: with KEEP, a failing test's lab stayed up, its run directory kept `.kept` (listing the project) and thinkpol, labdns, censord, and the node listed them in /opt/thinkpol/bin; with KEEP, a test hung past `-timeout 60s` left its lab and its directory with `.kept`; a later passing run without KEEP removed its own directory and left both kept ones (and its sweep had removed a dead pre-takeover leftover); `make lab-down` removed both labs and both directories, and lab/bin with them.
- 2026-10-28 verified: `make lint`, `make test` green; `make lab-test` LAB_P=4 green on f4dd95c (after merging origin/rewrite with TP-138), no lab/bin left. The first run on f4dd95c failed only internal/dataplane TestTheOverlayComesBackAfterALinkBounce ("the TUN kept its IPv6 address going down: nothing to test", engine_lab_test.go:273), not TP-121 code; a run on 1e071c0 had passed it. Out of scope, for the orchestrator: that test reads the address right after `ip link set down` while a pending re-apply can put it back.
- 2026-10-28 in-progress → review
- 2026-10-29 review → has-errors (round 3: R3.1–R3.9)
- 2026-10-29 has-errors → in-progress, owner: agent-claude-tp121
- 2026-10-29 round 3 fixed (4f9352c): labctl down's sweep, under the lab/bin lock, first collects the ended runs' directories, then asks Docker which labs are up (only if one of them has `.kept`), then removes; a failed query keeps every kept directory and is reported (R3.1, R3.2). The `lab/.run/<project>` rule doesn't hold: `up` creates that directory before it waits for a lab slot and the subnet lock, and only a lab Docker lists gets it removed (`Down`, `downWhere`), so a run killed while waiting, or a kept lab whose `docker compose up` failed, would pin its kept directory past every `labctl down`. Accepted instead, in sweepBinRoot's comment: a `docker compose up` a dying run left running that hasn't created the lab when Docker answers; that lab comes up without binaries (R3.1). start reads `KeepEnv` once and passes `keep` to cleanup; cleanup's keep path calls `keep(project)`, which lists the lab in `.kept` before marking the directory kept, so a kept lab always has its line (R3.3). Comments and docs: start (R3.4), GoTestEach (R3.5), README Gotchas ends with TP-146 (R3.6), `runBinariesLive`'s `lab:` prefix (R3.7), doc.go reflowed, start's `prepare` call explained, DownCheckout's doc split (R3.9).
- 2026-10-29 tests (round 3), each mutation fails its test: TestLabctlDownAsksDockerAfterFindingTheEndedRuns (mutation: the sweep asks Docker before it collects the ended runs), TestLabctlDownKeepsKeptBinariesWhenDockerCantListLabs (fake docker failing the label query; mutations: a failed query keeps nothing; DownCheckout drops its errors), TestStartListsAKeptLabBeforeItStarts (start against a docker that fails every call, in a temporary checkout; mutation: start without its `recordLab`), TestCleanupKeepsAFailedLabsBinaries now passes `keep`, writes no `.kept` itself and runs the next run's sweep (mutations: `keep` without `recordLab`; cleanup ignores `keep`; cleanup keeps without `keep`). bindir_lab_test.go checks only the run directories created after it started (R3.8); mutation: labctl gotest skips `RemoveRunBinaries` → "left behind" (one lab run of that test).
- 2026-10-29 verified: `make lint`, `make test` green; `make lab-test` LAB_P=1 (another checkout's labs running) green on 42e4049 (4f9352c merged with origin/rewrite, board-only changes), no lab/bin left (only lab/.run/bin.lock), and the dead directory the labctl mutation run left was swept. Not verified: the orphaned `docker compose up` gap (accepted, R3.1); the `-timeout` path with KEEP was not re-run this round (start's `.kept` line is now unit-tested).
- 2026-10-29 in-progress → review
- 2026-10-29 takeover (round 4, after the fixer died at 2ed9d71): re-read 27403d6 against R4.1–R4.7; every item was in, nothing left to finish.
- 2026-10-29 round 4 fixed (27403d6): README and start's comment name the accepted orphaned-compose gap (R4.1); sweepBinRoot's comment judges liveness at each run's lock check (R4.2); `labLister` type (R4.3); `startTB` records `Cleanup` calls, the test fails on any, and its comment lists the TB methods start may call (R4.4); TestTheSweepReportsAFailedListOfLabs (R4.5); recordLab writes "\n"+project+"\n" (R4.6); bindir_lab_test.go's comment says where the snapshot is taken and that its mutant may survive a concurrent sweep (R4.7).
- 2026-10-29 tests (round 4), each mutation run and failing its test: TestTheSweepReportsAFailedListOfLabs (mutations: the sweep drops a failed labsUp's error, i.e. no `errs = append(errs, err)`; a failed labsUp keeps nothing; keepAll also keeps unkept ended directories), TestRecordLabStartsOnALineOfItsOwn (mutation: recordLab without the leading newline → one glued project), TestStartListsAKeptLabBeforeItStarts (mutation: start registers its clean-up without a lab).
- 2026-10-29 verified: `make lint`, `make test` green; `make lab-test` LAB_P=4 green on 2ed9d71 (27403d6 merged with origin/rewrite at cd1e3f3), no lab/bin left. Other agents' labs came up between the concurrency check and the run, so it ran at LAB_P=4 beside them. Not verified: the orphaned `docker compose up` gap (accepted); the `-timeout` path with KEEP was not re-run.
