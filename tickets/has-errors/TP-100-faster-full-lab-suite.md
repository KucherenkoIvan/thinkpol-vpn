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

- full `make lab-test` after round 4: 154 s (2:34) wall at b876e8c (2026-10-19 08:57 UTC), same machine, quiet — 0 `tplab-*` containers immediately before and after, `LAB_P=4` and `THINKPOL_LAB_MAX_LABS` at defaults, `docker ps` clean after; the first of the two runs that morning passed in 197 s (3:17) under the same check. Before the branch: 336.3 s at be6e24a (2026-10-18; the rounds' timings are in the Log).

TestCensorMatrix, corrected in round 2: each cell takes its own lab slot (`lab.StartOwnSlot`), so `THINKPOL_LAB_MAX_LABS` bounds the matrix's labs — up to six at once — together with every other run's; round 1 shared one slot across all eight cells and so dodged the cap. The off cell is a non-parallel t.Run and the censored cells read its result instead of waiting on a channel: a censored cell whose baseline didn't run (a `-run` filter such as `TestCensorMatrix/udp/block-ip` selects one alone) fails fast instead of hanging, and with a low `-test.parallel` the censored cells can no longer fill every parallel slot while waiting. The gate itself is kept (a transport must pass without a censor before it is judged against one); round 3 dropped `TestFilteredMatrixRun`, round 2's subprocess regression check for the filtered `-run`, and the test's doc states the fail-fast rule instead.

Other cheap wins looked at, not done:
- Node start cost (~2.5 s per package) is no longer on the critical path at all: the whole in-node phase finishes under the `lab/` phase.
- The lab image is already shared across checkouts by its Dockerfile+platform hash tag; the before-run in a fresh worktree rebuilt nothing.
- The first ~10 s of the in-node phase (compiling its 34 test binaries) now overlaps the `lab/` phase's compile instead of adding on.

## Review findings
- [ ] R5.1 internal/agent/supervisor/egress_linux_test.go ~581-588: in bound=true the loop calls refused() (which writes on root, refreshing the conntrack flow) before rootFlow(), so the guard can't see an expired flow. Check the flow ONCE right after awaitDrops and before any write ("the root's conntrack flow expired before the forged errors were counted: the test proves nothing"); then the refused() loop.
- [ ] R5.2 rootFlow: match the original direction's tuple exactly as one contiguous string with a trailing space ("src=<root> dst=<internet> sport=<port> dport=<port> ") on a udp line, so 4000 can't match 40001; rename it rootFlowTracked. Read /proc/thread-self/net/nf_conntrack (or explain why /proc/net is safe here: the supervisor's nsthread can put the main thread in another namespace).
- [ ] R5.3 Each tick the forger sends port-unreachable then frag-needed to the same flow; frag-needed sets sk_err = EMSGSIZE and usually overwrites ECONNREFUSED. In bound=true treat ANY socket error from the write/read as a leak (or use IP_RECVERR and drain the error queue) — say which and why. In bound=false make sure the negative control doesn't depend on winning a wake-up race (count EMSGSIZE as "an error got through" too if that's what the control means). Update refused()'s comment to say what it really observes.
- [ ] R5.4 The 7-line comment at ~493-499 keeps only the constraint: "The root's socket whose flow the forged errors quote. An unreplied UDP flow expires (nf_conntrack_udp_timeout), so it is opened just before the errors are sent."
- [ ] R5.5 lab/results_test.go ~116-125: one string per gate used for both record and Fatal ("the off cell didn't run"; "the off cell didn't pass"), since the subtest path names transport and censor. Reflow the doc at ~25-27.
- [ ] R5.6 lab/lab.go ~53-58 StartOwnSlot doc: "StartOwnSlot is Start with one slot per test or subtest (keyed by its full name) instead of one per top-level test, held until that test ends … Don't mix it with Start, or nest it under a test that holds a slot of its own: the parent holds its slot while its subtests wait here."
- [ ] R5.7 Ticket Notes: one timing fact ("Timed make lab-test, same machine, no other lab running, defaults: 336.3 s at be6e24a before, 154 s at b876e8c after; per-round timings are in the Log."); the TestCensorMatrix paragraph states what is true now, no round history; "is not on the critical path", "overlaps"; one Notes line on why the supervisor's forged-ICMP test is fixed on this branch (its expired-flow flake failed this ticket's timed runs; the fix tightens what it asserts).
- [ ] R5.8 Log line with "08:14 UTC"/"08:57 UTC": written in the round under review and not merged, so rewrite it once without clock times or narration: "- 2026-10-19 full make lab-test twice at b876e8c, defaults: pass in 197 s (3:17) and 154 s (2:34), no other lab running; make lint, make test green". Then check the whole ticket for any other clock time.

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
- 2026-10-19 round 4, in e09dbde and b876e8c: the off-cell gate marks the cell errored before `runCell` can stop it, so a failed baseline reads "the transport failed without a censor", not "the off cell didn't run"; `TestM0`'s subtests each hold their own slot (`lab.StartOwnSlot`); `lab.StartOwnSlot` keys its slot `own:` and its doc (and lab/README.md's cap paragraph) warn against mixing it with `lab.Start` in one top-level test; the host-wide lock docs name the image-build lock, one `image.lock` for every tag; lab/README.md's two-phase paragraph says a concurrent run competes with all of this run's labs at once; the supervisor's forged-ICMP test opens the root's flow just before the forged errors and refreshes it on every poll (the write reports a pending ECONNREFUSED), and `bound=true` asserts the conntrack entry exists while it checks for leaks
- 2026-10-19 proved the forged-ICMP fix with `net.netfilter.nf_conntrack_udp_timeout` lowered to 1 s in the node (temporary, uncommitted edit, `COUNT=3`): the old test failed `bound=false` all 3 times ("refused false" — the expired flow, not the binding) while `bound=true` passed vacuously; with the fix, both subtests pass 3 of 3
- 2026-10-19 full `make lab-test` twice at b876e8c, defaults: pass, 197 s (3:17), 08:14 UTC, 0 `tplab-*` containers before and after (another run's labs appeared after it ended); pass, 154 s (2:34), 08:57 UTC, quiet machine (waited ~34 min, polling, for the other run's labs to clear; 0 before and after); `make lint`, `make test` green on this branch
- 2026-10-19 in-progress → review
- 2026-10-19 review → has-errors — round 5: review findings
