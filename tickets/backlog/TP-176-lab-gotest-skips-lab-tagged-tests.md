---
id: TP-176
title: "Lab: `make lab-gotest` silently skips lab-tagged tests"
milestone: M2
area: lab
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
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
- [ ] `make lab-gotest PKG=./lab/prototypes/reality` runs `TestRealityClientInterop` (not skipped)
- [ ] a lab-gotest run in which every test skipped exits non-zero, or prints a warning naming the package (the implementer picks one and says why in Notes)
- [ ] `lab/README.md` says which packages `lab-gotest` takes
- [ ] `make lint`, `make test` pass

## Notes
- Found 2026-11-07 by TP-175's implementer. Check whether any done ticket's Log cites `make lab-gotest` on a lab-tagged package as evidence (grep tickets/done for `lab-gotest PKG=./lab`), and list them here.
- Checked 2026-11-07 (grep of tickets/done for `lab-gotest`; lab-tagged packages are `./lab` and `./lab/prototypes/reality`; `./lab/censor` has no lab-tagged files):
  - TP-175 cites `make lab-gotest PKG=./lab/prototypes/reality` as passing, and its Log records that `TestRealityClientInterop` skipped. The evidence is affected.
  - TP-024 and TP-089 cite `make lab-gotest PKG=./lab/censor/...`. That package is not lab-tagged, so their lab-gotest citations are not affected. TP-024 also lists `TestCensorMatrix`, which lives in `./lab/results_test.go` (lab-tagged); its Log does not say which command ran it, so that claim is unverified by this check.
  - No other done ticket cites `lab-gotest` on a `./lab` package.

## Log
- 2026-11-07 created in backlog
