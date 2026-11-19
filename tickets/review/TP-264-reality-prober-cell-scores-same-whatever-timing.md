---
id: TP-264
title: "The reality × active prober gate cell scores the same way whatever the timing; not-judged cells are counted"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-255]
refs: []
owner: "agent-tp-264"
branch: "tp-264-prober-cell-deterministic"
---

## Goal
After TP-255 the reality × active prober cell scores `not judged` when the prober's baseline is short or the upstream tell unattributable, but an attributable tell over a long baseline (past about 11 s with setup's dials in it) still scores `pass`. So the gate cell can still flip by timing. No run has hit it yet: the long baselines sat at 8.07 to 8.25 s. And `not judged` cells are counted nowhere (unlike KNOWN FLAKES), so a second cell drifting to `not judged` would go unnoticed.

## Scope
The owner picks one of these (TP-223 R4 accepted both `pass` and `not judged` for the cell; TP-029's M2 wording says reality passes every M2 module):
- (a) In report mode, score the cell on the tell alone: any reported tell scores `not judged`, with the counts and times kept in the detail as evidence.
- (b) Pin the expectation: the cell must be `not judged`, and a `pass` fails the run.

Either way, count `NOT JUDGED: n (cells)` in RESULTS.md's header and in `make lab-test`'s last line, as KNOWN FLAKES is counted.

## Out of scope

## Acceptance
- [x] The owner's choice recorded (owner, date). Notes: (owner, 2026-11-19): a; also in lab/censor/doc.go, lab/README.md, docs/design/lab.md, docs/design/milestones.md and the matrix's comments.
- [x] The cell's verdict no longer depends on the baseline's length (unit test with a long baseline). TestUnjudged: a reported tell over a baseline past 11 s (8 dials in 5.52 s of probes, 8 in 12 s outside) is not judged (old code: pass, mutation M1), short and unattributable still not judged, flag-mode blocks still judged; TestUpstreamTellReportedOverAnyBaseline: report mode ends every tell with UpstreamTellReported over short and long baselines, flag mode still flags. Lab: relay-tcp × active prober fails (flag mode), reality × active prober not judged.
- [x] NOT JUDGED counted in RESULTS.md and the last line (tests). TestNotJudgedCounted (RESULTS.md header after KNOWN FLAKES, the test log's summary), TestWriteMatrixShareFlakes (per-stream not-judged-<stream>.txt beside the shares), TestMakefileCountsCells (make lab-test's LAB_COUNT_CELLS: each cell once across streams, sorted, nothing when none; every last line, FAILED included, ends with both counts). Lab: the matrix's log said `NOT JUDGED: 1 (reality / active prober)`.
- [x] TP-029's wording matches (owner). Its Scope: reality's active prober cell is `not judged` by design (owner, 2026-11-19: a), and reality passes every other M2 module; docs/design/milestones.md's M2 row says the same.

## Notes
- Owner's choice (owner, 2026-11-19): a. In report mode the reality × active prober cell is scored on the tell alone: any reported upstream tell scores `not judged` (the counts and times stay in the detail as evidence), so the verdict never depends on the baseline's length.
- TP-255's Notes ("What's left") give the numbers: the tightest run had 8 dials in 8.25 s outside the probes against 8 in 5.52 s of probes, so a baseline past about 11 s with no more dials read `pass` before this ticket.
- Lab cells (targeted, commit f3886297): relay-tcp (reference) × active prober `fail` (drop, upstream tell, 8 dials in 7.527 s of probes, 1 in 628 ms outside); reality × active prober `not judged` (that run's tell was unattributable, 8 dials in 5.521 s of probes, 8 in 8.109 s outside; the long-baseline reported path is unit-tested, no run hit it); the four labs took 87 s. No full lab (brief: targeted cells only).

## Log
- 2026-11-19 created in backlog (TP-255 review)
- 2026-11-19 backlog → in-progress, owner: agent-tp-264
- 2026-11-19 (a) implemented: unjudged scores any reported upstream tell not judged (censor.UpstreamTellReported), flag mode unchanged; NOT JUDGED counted in RESULTS.md's header, the matrix's test log and make lab-test's last line (LAB_COUNT_CELLS, per-stream not-judged lists); TP-029, lab/censor/doc.go, lab/README.md, docs/design/lab.md and milestones.md updated
- 2026-11-19 mutations, all killed: M1 unjudged reads the short baseline instead of the reported tell (TestUnjudged, the old code); M2 report mode drops UpstreamTellReported and M3 report mode flags a long-baseline tell (TestUpstreamTellReportedOverAnyBaseline); M4 cells not judged unsorted and M5 RESULTS.md header without NOT JUDGED (TestNotJudgedCounted); M6 a stream writes no not-judged list (TestWriteMatrixShareFlakes); M7 sort without -u and M8 the passed line without NOT JUDGED (TestMakefileCountsCells)
- 2026-11-19 make lint, make test green (commit f3886297); lab-tagged unit tests green; targeted lab cells reality and relay-tcp × active prober as expected (Notes). Not verified: a lab run where reality's tell is attributable over a long baseline (unit-tested only); no full lab, per the brief
- 2026-11-19 in-progress → review
