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
- [ ] The owner's choice recorded (owner, date).
- [ ] The cell's verdict no longer depends on the baseline's length (unit test with a long baseline).
- [ ] NOT JUDGED counted in RESULTS.md and the last line (tests).
- [ ] TP-029's wording matches (owner).

## Notes
- Owner's choice (owner, 2026-11-19): a. In report mode the reality × active prober cell is scored on the tell alone: any reported upstream tell scores `not judged` (the counts and times stay in the detail as evidence), so the verdict never depends on the baseline's length.
- TP-255's Notes ("What's left") give the numbers: the tightest run had 8 dials in 8.25 s outside the probes against 8 in 5.52 s of probes, so a baseline past about 11 s with no more dials reads `pass`.

## Log
- 2026-11-19 created in backlog (TP-255 review)
- 2026-11-19 backlog → in-progress, owner: agent-tp-264
