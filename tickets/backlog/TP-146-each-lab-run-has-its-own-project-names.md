---
id: TP-146
title: "Lab: each run has its own Compose project names"
milestone: M2
area: lab
repo: thinkpol-vpn
size: M
depends_on: [TP-121]
refs: []
owner: ""
branch: ""
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
- [ ] `make lab-gotest PKG=<a package in lab-test's node phase>` started during `make lab-test` from the same checkout: both pass, and neither run's clean-up removes the other's labs
- [ ] two `make lab-gotest` of one package started together from one checkout both pass
- [ ] `labctl down` still removes every lab of the checkout, kept ones included
- [ ] lab/README.md Gotchas no longer says to set `THINKPOL_LAB_PROJECT` for a second run
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Follow-up to TP-121 review finding R1.10 (paranoid 3): TP-121 documented the collision as out of scope, and its round-2 reviewer (torvalds) asked for this ticket.
- Compose project names have a length limit and `overridePattern` caps the override at 40 characters; check that the longest name (override, `-gotest-`, run id, hash) still fits.

## Log
- 2026-10-29 created in backlog (TP-121 R1.10 follow-up)
