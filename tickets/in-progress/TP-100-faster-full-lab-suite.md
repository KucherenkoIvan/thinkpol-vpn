---
id: TP-100
title: "Faster full lab suite"
milestone: M2
area: lab
repo: thinkpol-vpn
size: S
depends_on: []
owner: agent-opus
branch: tp-100-faster-full-lab-suite
---

## Goal
A full `make lab-test` on a quiet machine finishes in roughly three to four minutes wall time instead of the two serial phases that dominate today.

## Scope
- Run the `lab/` test phase and the in-node `labctl gotest` phase of `make lab-test` concurrently: one exit status, both logs still readable (`Makefile` around 121–127).
- Split `TestCensorMatrix` (`lab/results_test.go` around 30) so its cases run as parallel subtests within the lab slot cap, shortening the ~2 minute floor that phase sets today.
- Document in `lab/README.md` when to pass `LAB_P=1` (another lab run is already going) versus the default parallelism.

## Out of scope
- Changing what the lab proves; perf gates (`make lab-perf`) and `THINKPOL_LAB_MAX_LABS` policy.
- Automatic throttling of `LAB_P` by host load (decision in TP-055: fixed default, lower by hand).

## Acceptance
- [ ] wall time of a full `make lab-test` recorded before and after on the same machine with no other lab running; target about 3–4 minutes
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).
Measured 2026-10-18 at bbe4873 with `LAB_P=1`: `lab/` phase ~3:30 wall (tests parallel, sum ~7:19; `TestCensorMatrix` ~2:00 is the floor); in-node package phase ~5:40 (34 packages serially; tests ~4:16 plus ~2.5 s node start each); the two phases run one after the other.

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-18 backlog → in-progress — owner: agent-opus, branch: tp-100-faster-full-lab-suite
