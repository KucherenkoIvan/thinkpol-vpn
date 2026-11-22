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
owner: ""
branch: ""
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
- [ ] `RUN='^TestX$'` and `RUN='^A$/^B$'` reach labctl's `-run` byte for byte (and `SKIP` likewise), by a test; mutation named in the Log.
- [ ] lab/README.md shows the plain form.

## Notes

## Log
- 2026-11-22 created in backlog (final-lab small fixes)
