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
- [ ] R2.1 labctl down's sweep removes kept directories whose labs are still up (another `THINKPOL_LAB_PROJECT`, Docker failing partway, two spellings of one checkout): record each kept lab's project in `.kept`, remove a kept directory only when none of its projects is up; test `DownCheckout`'s sweep with two kept projects, one still up (paranoid 1, torvalds S1)
- [ ] R2.2 a `-timeout` hang with `THINKPOL_LAB_KEEP` leaves no `.kept`: mark at creation when KEEP is set, unmark in `remove` if no lab was kept (paranoid 2)
- [ ] R2.3 the exported `Up` skips R1.3's Main check: delete it, callers use `up(…, processBinaries)` (torvalds S2)
- [ ] R2.4 `buildTestsOnce` caches a failed build for the process: cache successes only, with a test (paranoid 4, torvalds S3)
- [ ] R2.5 a failed removal stays cached, unlocked and half-deleted: forget the entry anyway and leave the directory to the sweep; fix the doc; R1.8's last clause changes (paranoid 3, torvalds S4)
- [ ] R2.6 lab/doc.go still says nothing is shared between tests, "the test binaries GoTest runs once" misparses, and the doc/README "together with the lab" line is false (torvalds S5, paranoid 1)
- [ ] R2.7 no real `THINKPOL_LAB_KEEP` run: one manual run of a failing throwaway lab test, `.kept` and binaries survive, `make lab-down` removes both; logged (torvalds S6)
- [ ] R2.8 no test fails when `cleanup` drops `keepBinaries` or `DownCheckout` drops its sweep, or when a failed removal's entry is kept (paranoid 5, torvalds S6)
- [ ] R2.9 R1.17 partial: errors from `tryLockMode`, `RemoveAll`, `removeIfEmpty`, `runDirLive` lack the `lab:` prefix (paranoid 6)
- [ ] R2.10 one unremovable leftover fails every lab start: make the run's own sweep best-effort (paranoid 7)
- [ ] R2.11 naming: one word for run/process binaries (`runDirPrefix`, `runDirLive` vs `Lab.runDir`), and `binaries` → `labInputs` since it also builds the image (torvalds N1, N2)
- [ ] R2.12 the `if err == nil` cascade in `up` (torvalds N3)
- [ ] R2.13 goBuild's dead "a package that lost its tests" branch (torvalds N4)
- [ ] R2.14 `fatalTB` depends on `start` calling `Name` before `up`: say so (torvalds N5)
- [ ] R2.15 the kept-marker check is written three times: one `keptBy` helper (torvalds N6)
- R1.10 follow-up (per-run project identity in names and `down -tests`): a backlog ticket, filed by the orchestrator (torvalds); not in this ticket.

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
- 2026-10-28 out of scope (R1.10): `lab-gotest` beside `lab-test` (or two `lab-gotest` of one package, or two `lab-test`) from one checkout still share Compose project names (`<prefix>-gotest-<pkg hash>`, test labs), so one replaces the other's lab mid-test, and `lab-test`'s final `down -tests` removes the other run's labs; fixing it needs a per-run identity in project names and in `down -tests`. Documented in README "Gotchas" with the workaround (`THINKPOL_LAB_PROJECT` for one run). Binaries no longer collide.
- 2026-10-28 tests (round 1): bindir_test.go TestAKeptLabsBinariesStayUntilLabctlDown (mutations: remove ignores `.kept`; the sweep ignores `.kept`; labctl down's sweep skips kept dirs), TestRunDirectoriesWaitForTheCheckoutLock (mutations: newRunBinaries without lockBinRoot; remove without it), TestStartWithoutMainFails (mutation: no Main check in start), TestTestBinariesAreBuiltOncePerDirectory (mutation: no sync.Once), and the reworked TestRemoveRunBinariesForgetsTheRun (mutation: the entry kept) and TestRunsHaveTheirOwnBinaryDirectories (mutation: the sweep removes live dirs); each mutation fails its test. The lab test's "labctl skips its removal" check only holds when no other run from the checkout sweeps first (paranoid 6); not re-mutated this round.
- 2026-10-28 verified (round 1): `make lint`, `make test` green; `make lab-test` LAB_P=1 (other labs running) green on 6ab102a, no lab/bin left (only lab/.run/bin.lock). Not verified: a real `THINKPOL_LAB_KEEP` failure kept with its binaries (unit-tested only); the lab test's mutations were not re-run.
- 2026-10-28 in-progress → review
- 2026-10-28 review → has-errors (round 2: R2.1–R2.15)
- 2026-10-28 has-errors → in-progress, owner: agent-claude-tp121
