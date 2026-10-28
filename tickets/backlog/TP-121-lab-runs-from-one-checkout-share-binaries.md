---
id: TP-121
title: "Lab: two runs from one checkout don't rebuild each other's binaries"
milestone: M2
area: tests
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
Two lab runs from the same checkout at the same time (two `make lab-gotest`, or `lab-gotest` beside `lab-test`) each run the binaries they built.

## Scope
- Today every run builds into the one `lab/bin` of the checkout: the test binaries at `lab/bin/tests/<pkg>.test` (`lab/gotest.go`, `goTest`) and `thinkpol`, `labdns`, `censord` (`lab/prepare.go`). A second run rebuilds a file a running container has open or is about to exec, and the first run fails with errors like `fork/exec /proc/self/exe: no such file`.
- Give each run its own binary directory (per lab, or per process), mounted where `BinDir` points in the container, and remove it when the lab is torn down. Keep `make lab-test`'s single run as fast as today: no extra builds when only one run is going.
- A lab test that builds while another run uses the same checkout passes.

## Acceptance
- [ ] two `make lab-gotest` runs of different packages started together from one checkout both pass
- [ ] no `lab/bin` directories are left behind after either run ends (passed, failed or interrupted)
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Seen during TP-120 (2026-10-21) when two reviewers ran lab tests from one worktree.
- **Slot (pre-M2 phase, 2026-10-24).** Wave 0, first in the phase.

## Log
- 2026-10-22 created in backlog (TP-120 out-of-scope note)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 0)
