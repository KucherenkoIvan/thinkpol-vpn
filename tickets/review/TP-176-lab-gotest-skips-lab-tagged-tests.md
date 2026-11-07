---
id: TP-176
title: "Lab: `make lab-gotest` silently skips lab-tagged tests"
milestone: M2
area: lab
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-176"
branch: "tp-176-lab-gotest-skips-lab-tagged-tests"
---

## Goal
`make lab-gotest PKG=<pkg>` runs every test the package has for the lab, or fails loudly. It never reports green on a package whose tests all skipped.

## Scope
- `labctl gotest` builds test binaries without `-tags lab`, so files with `//go:build lab` (all of `lab/*_test.go` and `lab/prototypes/reality`) are not compiled in, and the run passes with nothing tested. TP-175 saw `TestRealityClientInterop` skip under `make lab-gotest PKG=./lab/prototypes/reality`.
- Fix it either by building the test binaries with `-tags lab`, or by refusing a PKG that needs the tag. Either way, a run in which every test skipped is reported as a failure, or at least as a loud warning that names the package.
- `make lab-test` uses `-tags lab` for `./lab/...` and is not affected; leave it as it is.

## Out of scope
- Changing which tests carry the `lab` tag.

## Acceptance
- [x] `make lab-gotest PKG=./lab/prototypes/reality` runs `TestRealityClientInterop` (not skipped): the host run (`go test -tags lab`) runs `TestRealityPrototype`, whose in-node run shows `--- PASS: TestRealityClientInterop` and its three subtests passing; `gotest: ok`
- [x] a lab-gotest run in which every test skipped exits non-zero, or prints a warning naming the package (the implementer picks one and says why in Notes): exits non-zero; `make lab-gotest PKG=./lab/prototypes/reality RUN=TestRealityClientInterop` printed `gotest: every test skipped in: …/lab/prototypes/reality` and make exited 2. Tests: `TestGotestVerdict`, `TestOnlySkippedCountsEveryRunOfAPackage`, `TestTallyTestsCountsTopLevelResultsOnly`
- [x] `lab/README.md` says which packages `lab-gotest` takes (any pattern, `./lab/...` included; the tagged ones run on the host)
- [x] `make lint`, `make test` pass (on 8224638)

## Notes
- Found 2026-11-07 by TP-175's implementer. Check whether any done ticket's Log cites `make lab-gotest` on a lab-tagged package as evidence (grep tickets/done for `lab-gotest PKG=./lab`), and list them here.
- Checked 2026-11-07 (grep of tickets/done for `lab-gotest`; lab-tagged packages are `./lab` and `./lab/prototypes/reality`; `./lab/censor` has no lab-tagged files):
  - TP-175 cites `make lab-gotest PKG=./lab/prototypes/reality` as passing, and its Log records that `TestRealityClientInterop` skipped. The evidence is affected.
  - TP-024 and TP-089 cite `make lab-gotest PKG=./lab/censor/...`. That package is not lab-tagged, so their lab-gotest citations are not affected. TP-024 also lists `TestCensorMatrix`, which lives in `./lab/results_test.go` (lab-tagged); its Log does not say which command ran it, so that claim is unverified by this check.
  - No other done ticket cites `lab-gotest` on a `./lab` package.
- Chose failure over a warning (2026-11-07): a warning scrolls past while the exit status stays green, and the green exit status is what a ticket cites as evidence. Fixed by building with the tag, not by refusing the PKG: `labctl gotest -tagged` also runs packages with lab-tagged tests on the host (`go test -tags lab`, as `make lab-test`'s lab phase does), since a node has no Docker to start the labs those tests need. `-fail-skipped` (implies `-v`) fails a package whose tests all skipped over both runs, and a run in which no test ran. `make lab-gotest` passes both flags; `make lab-test` passes neither.
- `RUN` applies to both runs, so an in-node test that a lab test drives is reached through the lab test: `RUN=TestRealityPrototype`, not `RUN=TestRealityClientInterop` (that one now fails loudly; lab/README.md says so).

## Review findings
- [x] R1.1 (should-fix) `lab/gotest.go` `GoTestLabTagged` runs `go test` with no process group, Cancel or WaitDelay: on cancel only `go` dies, the test binary keeps the output pipe, so `cmd.Run` waits up to its `-test.timeout`, and if that timeout panics its `t.Cleanup` never runs and labs stay up. Run the child in its own process group, signal the group on cancel, set WaitDelay; unit test if practical.
- [x] R1.2 (should-fix) `Makefile` `lab-gotest` with PKG unset defaults to `./...`, which with `-fail-skipped` is red by construction and runs the whole `./lab` suite on the host under one 60m limit. Require PKG (a make error naming it) and say so in lab/README.md (`make lab-test` runs everything).
- [x] R1.3 (should-fix, docs) `lab/doc.go` says lab-tagged tests run through `make lab-test`; `make lab-gotest` now runs them too for the packages it's given. Update it.
- [x] R1.4 (should-fix, small) `ListLabTaggedPackages` compares test-file counts, so a `//go:build !lab` file paired with a `//go:build lab` file is missed. Compare file names; add a `!lab`/`lab` pair to the test module.
- [x] R1.5 (nits) `lab/gotest_test.go`: the same GOWORK/GOFLAGS environment for the listing test and `TestGoTestLabTagged…`; `labctl` `-timeout` help's default; lab/README.md: COUNT also repeats the host lab tests; `lab: ` prefix on the `lab tests in …` error; unit tests for the "no packages with tests" `-fail-skipped` branch and for `GoTestEach` keeping its tally (or say in the Log they're covered only by the manual run).

## Log
- 2026-11-07 created in backlog
- 2026-11-07 backlog → in-progress, owner: agent-tp-176
- 2026-11-07 implemented (65a1adf, previous agent): `labctl gotest -tagged -fail-skipped`, `lab.ListLabTaggedPackages`, `lab.GoTestLabTagged`, `lab.TallyTests`/`OnlySkipped`, `gotestVerdict`; Makefile `lab-gotest` passes both flags; lab/README.md section
- 2026-11-07 took over after the pause; verified 65a1adf, merged origin/rewrite (b775d5e); `make lint`, `make test` green
- 2026-11-07 mutations, each killed: TallyTests prefix → Contains (TestTallyTests…); OnlySkipped per result instead of per package (TestOnlySkipped…); ListLabTaggedPackages `<=` → `<` (TestListLabTagged…); GoTestLabTagged without `-tags=lab` (TestGoTestLabTagged…); gotestVerdict without the no-test-ran check, without the all-skipped check, and without failed packages (TestGotestVerdict)
- 2026-11-07 `make lab-gotest PKG=./lab/prototypes/reality` on b775d5e: exit 0, in-node `--- PASS: TestRealityClientInterop` (3 subtests) inside `TestRealityPrototype`; with `RUN=TestRealityClientInterop`: exit 2, "every test skipped in: …/lab/prototypes/reality"
- 2026-11-07 full `make lab-test` on d35561a failed in the node phase: `./lab`'s new untagged tests exec `go`, and a node has none; also `internal/dataplane/path` `TestRelayDelivers/datagram` ("hello B" never arrived), out of scope, passed on the next full run. An earlier full run was killed by its time limit while it waited for the lock (no result)
- 2026-11-07 8224638: the go-command tests skip when `go` is not in PATH (checked: they skip with PATH emptied, pass on the host); `make lint`, `make test` green
- 2026-11-07 full `make lab-test` (LAB_P=4, exclusive CPU lock) on 8224638: exit 0, no FAIL
- 2026-11-07 in-progress → review
- 2026-11-07 review → has-errors (round 1 findings R1.x)
- 2026-11-07 R1.1: `GoTestLabTagged` starts `go test` in its own process group (lab/procgroup_unix.go), cancel SIGKILLs the group (a test binary has no signal handler, so no gentler signal lets its cleanups run), WaitDelay 10s for a process that left the group; doc says a cancelled run leaves its labs, `make lab-down` removes them. Test `TestGoTestLabTaggedCancelKillsTheTestBinary` (lab/gotest_unix_test.go); mutation: no `killGroupOnCancel` call → "test binary … still alive after cancel". WaitDelay alone has no test (with the group kill a test can't tell it apart)
- 2026-11-07 R1.2: `make lab-gotest` without PKG stops with a make error naming PKG and pointing to `make lab-test`; lab/README.md says why. Checked by hand: `make lab-gotest` → "lab-gotest needs PKG …"
- 2026-11-07 R1.3: lab/doc.go says make lab-gotest runs the lab-tagged tests of the packages it's given (labctl gotest -tagged)
- 2026-11-07 R1.4: `ListLabTaggedPackages` compares test file names; test module gained a `//go:build !lab` / `//go:build lab` pair; mutation: back to comparing counts → TestListLabTagged… fails (pair missed)
- 2026-11-07 R1.5: both go-command tests use `isolateGoEnv` (GOWORK=off, GOFLAGS=-mod=mod via t.Setenv); `-timeout` help names both defaults; README: COUNT also repeats the host lab tests; error is `lab: lab tests in …`; new `TestGotestWithNoPackagesWithTests` (labctl), mutation: drop the `-fail-skipped` branch → "want a no-packages error". `GoTestEach` keeping its tally needs Docker: covered only by the manual `make lab-gotest` runs, no unit test
- 2026-11-07 merged origin/rewrite (76a1359; conflicts in lab/gotest.go, lab/labctl/main.go, lab/labctl/main_test.go with TP-146's run ids, kept both sides); `make lint`, `make test` green on 76a1359
- 2026-11-07 `make lab-gotest PKG=./lab/prototypes/reality` on 76a1359: exit 0, in-node `--- PASS: TestRealityClientInterop` (3 subtests) inside `--- PASS: TestRealityPrototype`, `gotest: ok`
- 2026-11-07 full `make lab-test` (LAB_P=1, another lab was up when it queued; exclusive CPU lock) on 76a1359: exit 0, no FAIL. Not required this round, run anyway on the final code commit
- 2026-11-07 has-errors → review
