---
id: TP-255
title: "reality × active prober scores pass on a short baseline although the tell was seen"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-255"
branch: "tp-255-prober-short-baseline"
---

## Goal
In `lab/censor/modules_prober.go` (`upstreamTally.unattributable`, `shortBaseline`, `prober.upstreamTell`), when the prober's baseline window (the time it watched server-1's host outside its probes) is shorter than the probing, the tell isn't called unattributable: the baseline is a wall-clock race between censord's start and the first probe, and gets worse under load. In report mode the module then returns "reported, not flagged", and `unjudged` in `lab/results_test.go` matches only "unattributable", so the gate cell reality × active prober scores `pass` while its detail says the tell was seen ("a baseline shorter than the probing, too short to call the tell unattributable"). Across runs the cell flips between `not judged` and `pass` with no code change (seen in TP-247's runs; it passed in 3 of 10 earlier runs on rewrite branches). Score a short baseline as not judged (or make the baseline window fixed), so the gate cell can't pass by timing.

## Scope
- Make a short baseline unable to score the cell `pass`: either the cell scores `not judged` (the report says why), or the prober watches a fixed baseline window before its first probe.
- Keep the long-baseline behaviour: a tell attributable to the probes is reported, an unattributable one scores `not judged`.

## Out of scope

## Acceptance
- [ ] The cause named in Notes, with the timing that makes the baseline short.
- [ ] A fix: reality × active prober never scores `pass` when the tell was seen on a short baseline.
- [ ] 10 targeted runs of the reality cell under load give the same score, and a mutation that brings the short-baseline pass back fails a test.
- [ ] No retries and no longer timeouts without a cause.

## Notes

## Log
- 2026-11-19 created in backlog (TP-247 review)
- 2026-11-19 backlog → in-progress, owner: agent-tp-255
