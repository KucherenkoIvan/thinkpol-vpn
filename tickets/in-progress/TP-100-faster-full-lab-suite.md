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
- after: recorded in round 1 as "152.3 s at 6373095", but that timing can't have run on 6373095 as pushed: the round-1 gate deadlocks on that tree (below), so the commit the run actually timed can't be named. Round 2 supersedes it: this branch at 51d76cf — 156.5 s wall on a quiet machine (0 `tplab-*` containers in three checks over 90 s before the run, and it passed; `lab` package 155.2 s, in-node phase finished under it, 34 packages at `-p 4`). Round 3 supersedes that: this branch at 4b58219 — 147.2 s wall on a quiet machine (0 `tplab-*` containers before and after, defaults, 34 packages at `-p 4`). The first round-3 attempt failed on `TestForgedICMPErrorsAreRefused/bound=false` (`internal/agent/supervisor`, a package this branch doesn't touch): passed `COUNT=3` alone right after, so a load flake, not a regression.

TestCensorMatrix, corrected in round 2: each cell takes its own lab slot (`lab.StartOwnSlot`), so `THINKPOL_LAB_MAX_LABS` bounds the matrix's labs — up to six at once — together with every other run's; round 1 shared one slot across all eight cells and so dodged the cap. The off cell is a non-parallel t.Run and the censored cells read its result instead of waiting on a channel: a censored cell whose baseline didn't run (a `-run` filter such as `TestCensorMatrix/udp/block-ip` selects one alone) fails fast instead of hanging, and with a low `-test.parallel` the censored cells can no longer fill every parallel slot while waiting. The gate itself is kept (a transport must pass without a censor before it is judged against one); round 3 dropped `TestFilteredMatrixRun`, round 2's subprocess regression check for the filtered `-run`, and the test's doc states the fail-fast rule instead.

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
- 2026-10-18 round 2: the matrix gate can't hang any more (off cell non-parallel, censored cells read its result; `TestFilteredMatrixRun` guards the filtered `-run`), each cell takes its own lab slot (`lab.StartOwnSlot`), `make lab-test` prefixes stderr through awk and fails if `labctl down -tests` fails (51d76cf)
- 2026-10-18 timed run, quiet machine, defaults: 156.5 s (2:37); `make lint`, `make test` green on this branch
- 2026-10-18 in-progress → review
- 2026-10-18 review → in-progress — round 3: review findings (owner: agent-opus)
- 2026-10-19 round 3, in 7c1e073 and 4b58219: top-level lab tests that need no ordering run parallel; the off-cell gate distinguishes "the off cell didn't run" from "it failed", recorded through one mutex-guarded helper; the matrix doc states the fail-fast rule with no counts or history; `TestFilteredMatrixRun` and the Go 1.21 loop-var copies are gone; `lab.StartOwnSlot` keys its slot by `t.Name()` (one slot per subtest by construction, its doc's warning gone); the cap docs (lab/README.md, `MaxLabsEnv`, the env table) all say per-subtest slots; a host-wide file lock serialises the lab image build across the two phases
- 2026-10-19 timed run, quiet machine (0 `tplab-*` containers before and after), defaults: 147.2 s (2:27) at 4b58219; first attempt failed on the supervisor ICMP flake (not this branch's code), `COUNT=3` alone green right after; `make lint`, `make test` green on this branch
- 2026-10-19 in-progress → review
- 2026-10-19 review → in-progress — round 4: review findings (owner: agent-opus)
