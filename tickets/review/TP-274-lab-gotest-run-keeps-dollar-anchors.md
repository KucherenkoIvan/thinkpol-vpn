---
id: TP-274
title: "make lab-gotest RUN=… loses `$` anchors"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: agent-tp-274
branch: tp-274-lab-gotest-run-anchors
---

## Goal
`RUN` (and `SKIP`) pass through make before the shell, so `make lab-gotest PKG=… RUN='^TestX$'` reaches `go test -run` without the `$` unless the user doubles it (`$$`), and `$/` in a subtest pattern is read as a make variable. A `RUN` regex should reach the test binary byte for byte, and lab/README.md should show the plain form.

## Scope
- Pass `RUN` and `SKIP` to labctl unexpanded.
- A test (make -n, or a small script test in the repo's style) that fails without the fix.
- lab/README.md: the plain form, and drop any doubled-`$` advice.

## Out of scope
- Other targets' hard-coded patterns in the Makefile (they are written in make syntax on purpose).

## Acceptance
- [x] `RUN='^TestX$'` and `RUN='^A$/^B$'` reach labctl's `-run` byte for byte (and `SKIP` likewise), by a test; mutation named in the Log. (TestMakefileLabGotestPassesRunVerbatim, lab/labgotestrun_test.go.)
- [x] lab/README.md shows the plain form. (the lab-gotest paragraph: `RUN='^TestCensorMatrix$/^udp$/^off$'`, no doubled `$$`; it had no doubled-`$` advice to drop.)

## Notes
- Cause: `lab-gotest: export LAB_RUN = $(RUN)` (Makefile): a variable set on make's command line or taken from the environment is recursively expanded, so expanding `$(RUN)` expands `$` and `$/` inside its value too. `$(value RUN)` (and `$(value SKIP)`) hands over the text as given; the recipe passes it on in double quotes (`-run "$$LAB_RUN"`), which the shell doesn't touch further.

## Review findings
- [x] R1.1 lab/labgotestrun_test.go: the inner make inherits the outer make's MAKEFLAGS (and MFLAGS, MAKELEVEL, GNUMAKEFLAGS) plus RUN/SKIP from the environment, because labctl passes the environment to go test. Run as `make lab-gotest PKG=./lab RUN=TestMakefileLabGotestPassesRunVerbatim`, the outer RUN reaches the inner make through MAKEFLAGS as a command-line value and beats the environment case: false failure. Strip MAKEFLAGS, MFLAGS, MAKELEVEL, GNUMAKEFLAGS, RUN and SKIP from the inner make's environment before setting the case's own; prove that exact command passes in the lab and the mutation (no stripping) fails it. (innerMakeEnv, lab/labgotestrun_test.go.)
- [x] R1.2 lab/labgotestrun_test.go: `out, _ := cmd.Output()` drops stderr, so a make that breaks for another reason shows only `got ""`. Include make's stderr in the failure message while still comparing only the value lines. (cmd.Stderr goes into the failure message; stdout alone is compared.)

## Log
- 2026-11-22 created in backlog (final-lab small fixes)
- 2026-11-22 backlog → in-progress, owner: agent-tp-274
- 2026-11-22 fix: Makefile lab-gotest exports LAB_RUN and LAB_SKIP as $(value RUN) and $(value SKIP); lab/README.md shows the plain form; TestMakefileLabGotestPassesRunVerbatim (lab/labgotestrun_test.go) runs make with a prerequisite that inherits the target's exports and prints them, RUN and SKIP from the command line and from the environment
- 2026-11-22 mutations: the unfixed Makefile ($(RUN), $(SKIP)): the test fails both ways (`^TestCensorMatrix^(udp|reality)^off`); only SKIP back to $(SKIP): fails both ways; restored: passes
- 2026-11-22 145f9d9b end to end in the lab: make lab-gotest PKG=./internal/agent/supervisor/ RUN='^TestEgressNotWorthAllowing$|^TestEgressErrorIsACode$' ran exactly those two tests, green; the same command on the unfixed Makefile failed with "labctl: gotest: no test ran" (`$|` eaten). A lone trailing `$` survives GNU make unfixed, a mid-pattern `$` doesn't; the test's patterns have both
- 2026-11-22 145f9d9b: make lint and make test green. No full lab: the change is the lab-gotest target only
- 2026-11-22 in-progress → review
- 2026-11-22 review → has-errors (R1.1–R1.2)
- 2026-11-22 has-errors → in-progress (R1.1–R1.2)
- 2026-11-22 R1.1: the inner make's environment drops MAKEFLAGS, MFLAGS, MAKELEVEL, GNUMAKEFLAGS, RUN and SKIP (innerMakeEnv); R1.2: make's stderr goes into the failure message, stdout alone is compared
- 2026-11-22 mutation: innerMakeEnv back to os.Environ(), the test run under an outer make given RUN=TestMakefileLabGotestPassesRunVerbatim on the command line: fails the environment case (got RUN=TestMakefileLabGotestPassesRunVerbatim, stderr shown); restored: passes
- 2026-11-22 c78ea31e: make lab-gotest PKG=./lab RUN=TestMakefileLabGotestPassesRunVerbatim green (the host-run lab-tagged pass ran it; the in-node pass skips, no make in the node); make lint and make test green
- 2026-11-22 in-progress → review
