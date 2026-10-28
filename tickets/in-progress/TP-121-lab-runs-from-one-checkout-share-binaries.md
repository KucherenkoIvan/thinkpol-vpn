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
- [ ] R1.1 a `THINKPOL_LAB_KEEP` lab loses its binaries: `Main` removes the run directory it mounts, and the next run's sweep would too; pin it with a kept marker that only `labctl down` sweeps (paranoid 1, torvalds 1)
- [ ] R1.2 drop `Main`'s signal handler (it hangs behind `preparedMu` during builds and swallows a second Ctrl-C); `Main` returns instead of calling `os.Exit`, interrupted runs are left to the sweep; restate "interrupted" (and "failed" for a `-timeout` panic) in the Log (paranoid 2, 7, torvalds 2, auto)
- [ ] R1.3 a lab package without `lab.Main` in its TestMain leaks its run directory silently; fail loudly in `start` (torvalds 3, auto)
- [ ] R1.4 unexported or unused exports: delete `Prepare`, unexport `RemoveStaleBinaries` (torvalds 5, 6, go-style 3)
- [ ] R1.5 no `standalone bool` in `up`: callers pass how the binaries are made; one clean-up path on error; rename `UpStandalone` to `UpDetached` (torvalds 7)
- [ ] R1.6 the `runDir` type clashes with `Lab.runDir` and the local in `up`; rename it after what it holds (torvalds 8, go-style 2)
- [ ] R1.7 the mechanism comment belongs in lab/doc.go, which still says nothing is shared (go-style 1)
- [ ] R1.8 `RemoveRunBinaries(ctx)` without a root (removes whatever this process holds; no `Root()` lookup at exit); labctl defers it only in gotest; don't forget an entry whose removal failed (torvalds 4, auto)
- [ ] R1.9 test binaries within one process are rebuilt over a file a parallel lab runs; build each package's tests once per process (torvalds 9)
- [ ] R1.10 `lab-gotest` beside `lab-test` (or two `lab-gotest` of one package) collide on Compose project names, and `lab-test`'s final `down -tests` removes the other run's gotest labs: fix if small, else document precisely in README and the Log as out of scope (paranoid 3)
- [ ] R1.11 delete the legacy sweep (pre-TP-121 `lab/bin` entries) (torvalds 10, paranoid 8)
- [ ] R1.12 unit tests leave a `bin-<hash>.lock` in TMPDIR on every `make test` (paranoid 9, go-style)
- [ ] R1.13 no test catches dropping the creation lock (`lockBinRoot` in `newRunDir`) (paranoid 5)
- [ ] R1.14 stale comments: lab/Dockerfile:2 "into lab/bin", the unwrapped renderCompose line (paranoid 10, torvalds 12, go-style 5)
- [ ] R1.15 README wording: the end of `make lab-test` skips the sweep with `THINKPOL_LAB_KEEP`; "Leftovers" omits binaries (go-style 9)
- [ ] R1.16 tests use `os.IsNotExist`; use `errors.Is(err, fs.ErrNotExist)` (go-style 6)
- [ ] R1.17 bare filesystem errors from `newRunDir` lack the `lab:` prefix (go-style 7)
- [ ] R1.18 `Up`'s doc comment runs two paragraphs together (go-style 4)
- [ ] R1.19 labctl usage overstates `-stale`: it removes no binaries (go-style 8, auto)
- [ ] R1.20 bindir_lab_test.go copies the sweep's liveness check; share one helper (torvalds 13)

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
