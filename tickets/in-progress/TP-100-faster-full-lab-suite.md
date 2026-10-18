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
- [x] wall time of a full `make lab-test` recorded before and after on the same machine with no other lab running; target about 3–4 minutes
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
Origin: design and code-quality review of rewrite at 2fa1191 (2026-10-18).
Measured 2026-10-18 at bbe4873 with `LAB_P=1`: `lab/` phase ~3:30 wall (tests parallel, sum ~7:19; `TestCensorMatrix` ~2:00 is the floor); in-node package phase ~5:40 (34 packages serially; tests ~4:16 plus ~2.5 s node start each); the two phases run one after the other.

Timing 2026-10-18, same machine, quiet (0 `tplab-*` containers checked before each run; none appeared mid-run), `LAB_P=4` default and `THINKPOL_LAB_MAX_LABS` default for both runs, `docker ps` clean after each:
- before: `origin/rewrite` at be6e24a, unchanged Makefile — 336.3 s wall (`lab` package 224.6 s, in-node phase the remaining ~112 s, 34 packages at `-p 4`).
- after: this branch at 6373095 — 152.3 s wall; `lab` package 151.1 s, in-node phase finished under it.

TestCensorMatrix: its cells now run as parallel subtests of the one top-level test, so they still hold the single lab slot `lab.Start` gives `test:TestCensorMatrix` — the parallelism does not widen the slot cap. Cells of the same transport were deliberately serial before only because a censored cell asserted its transport passed without a censor; that gate is kept (a transport's censored cells wait for its uncensored cell's result), everything else runs at once. Cells that run and pass take 6–42 s each; the whole matrix went from ~2:00 to 43 s alone.

Other cheap wins looked at, not done:
- Node start cost (~2.5 s per package) is no longer on the critical path at all: the whole in-node phase finishes under the `lab/` phase.
- The lab image is already shared across checkouts by its Dockerfile+platform hash tag; the before-run in a fresh worktree rebuilt nothing.
- The first ~10 s of the in-node phase (compiling its 34 test binaries) now overlaps the `lab/` phase's compile instead of adding on.

## Log
- 2026-10-18 created in backlog (code-quality review)
- 2026-10-18 backlog → in-progress — owner: agent-opus, branch: tp-100-faster-full-lab-suite
- 2026-10-18 `lab/` and in-node phases of `make lab-test` run at once (one exit status, `[lab]`/`[node]` line prefixes, tear-down after both); `TestCensorMatrix` cells parallel behind the uncensored-cell gate; `LAB_P=1` guidance in lab/README.md (6373095)
- 2026-10-18 first parallel-matrix version deadlocked (one buffered channel served only one of three waiters per transport); fixed with a close-broadcast; caught by `make lab-test` on a quiet machine, matrix 43 s alone
- 2026-10-18 timed runs, quiet machine, defaults: before 336.3 s (5:36), after 152.3 s (2:32); `make lint`, `make test` green on this branch
- 2026-10-18 in-progress → review
- 2026-10-18 review → in-progress — round 2: review findings (owner: agent-opus)
