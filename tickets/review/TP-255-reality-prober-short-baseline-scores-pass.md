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
- [x] The cause named in Notes, with the timing that makes the baseline short.
- [x] A fix: reality × active prober never scores `pass` when the tell was seen on a short baseline.
- [x] 10 targeted runs of the reality cell under load give the same score, and a mutation that brings the short-baseline pass back fails a test.
- [x] No retries and no longer timeouts without a cause.

## Notes
- **Cause.** The prober's baseline is the time it watched server-1's host outside its probes, counted from its start (`prober.Run` sets `started`), and censord starts right before the cell brings the transport up. So the baseline before the first probe is however long reality's setup took to send the first suspect connection, about 4.2 to 5.0 s or about 8.1 s in these runs, while the 7 probes take 5.5 to 7.6 s (each probe's answer and its 500 ms grace). server-1's setup dials to the site (7 or 8: REALITY dials its target for each of device-a's connections) land in the baseline either way. When the baseline is the longer one, the tell is unattributable (8 dials in about 8.1 s outside against 8 to 10 in the probing): `not judged`. When it's the shorter one, TP-223's guard (`upstreamTally.shortBaseline`) keeps the tell standing; in report mode the verdict was "reported, not flagged", and `unjudged` matched only "upstream tell: unattributable", so the cell scored `pass`. Which one a run got was a race between setup and probing. That flip is the cause, not load as such: the 10 runs below had labs starting in 1m24s to 5m41s, and the baselines stayed in the same two bands.
- **Fix: a reported tell over a short baseline scores `not judged`.** The verdict texts are exported constants (`censor.UpstreamTellUnattributable`, `censor.UpstreamTellShortBaseline`, lab/censor/modules_prober.go), and `unjudged` (lab/results_test.go) matches either. In flag mode a short baseline still flags (relay-tcp's own dial for the suspected client must not hide its tell, TP-223 R4.1), and a long baseline keeps its behaviour: attributable is reported (pass), unattributable is `not judged`. I chose this over a fixed baseline window: waiting before or after the probes adds wall time to every cell whose tell shows. It wouldn't make the verdict deterministic either, because the window's content is setup's burst of dials, whose share of any window depends on setup's length.
- **What's left.** The long-baseline case is unattributable only while setup's dials make at least half the probes' rate over the baseline. The tightest of the 10 runs had 8 dials in 8.25 s outside against 8 in 5.52 s of probes, so it would read `pass` if the baseline grew past about 11 s with no more dials. Across all runs here and in TP-223 the long baseline sat at 8.07 to 8.25 s whatever the load, so it has about 2.5 s of margin. If TP-230 removes device-a's extra connections, it doesn't change this: they come every 5 s and add at most one dial to either window.
- Old code at c9d0f06f, lab-gotest of the reality row × off and active prober, 3 runs: 2 not judged (long baseline), 1 pass ("9 dials in 7.551s of probes, 7 in 4.399s outside them, a baseline shorter than the probing, ...").
- New code at f0416e9c, lab-gotest of reality lab 2 × off and active prober, COUNT=10, alongside two other sessions' full labs (load 10 to 31 on the runner): 10 of 10 not judged. 7 were unattributable (outside 8.07 to 8.25 s), and 3 had a short baseline (4.20, 4.45 and 5.02 s outside against 5.60, 7.56 and 7.54 s of probing), which the old code would have scored pass.

## Review findings
- [x] R1.1 `unjudged` matched the short-baseline words in a flag-mode block's text too (relay-tcp): only accept verdicts count now, so a block's cell can't read not judged (TestUnjudged case + mutation).
- [x] R1.2 `unattributable`'s comment: the baseline before the first probe is however long setup took (about 4 to 8 s in the lab), not a second or two.
- [x] R1.3 lab/censor/doc.go: a long baseline (past about 11 s) still scores a reported tell pass; points to TP-264.

## Log
- 2026-11-19 created in backlog (TP-247 review)
- 2026-11-19 backlog → in-progress, owner: agent-tp-255
- 2026-11-19 cause found: the prober's baseline before the first probe is a race between censord's start and reality's setup, 4.2 to 5.0 s or about 8.1 s against 5.5 to 7.6 s of probing; a reported tell over the short one scored pass because unjudged matched only "unattributable"
- 2026-11-19 fix: censor.UpstreamTellUnattributable and censor.UpstreamTellShortBaseline exported; unjudged matches either, so a reported tell over a short baseline scores not judged; doc.go, lab/README.md and the RESULTS.md header say so; TestUnjudged gets short-baseline cases on either family
- 2026-11-19 mutation, killed: unjudged without the short-baseline match (TestUnjudged, "a short baseline" and "a short baseline on IPv6"); the guard that keeps the short-baseline words in the verdict is already pinned by TestUpstreamTellShortBaseline (TP-223)
- 2026-11-19 lab-gotest at c9d0f06f (old code) of the reality row × off and active prober, 3 runs: 2 not judged, 1 pass on a 4.4 s baseline; lab-gotest at f0416e9c of reality lab 2 × off and active prober, COUNT=10, under other sessions' full labs: 10 of 10 not judged (7 unattributable, 3 short baseline)
- 2026-11-19 make lint and make test pass at b75c677d (rewrite merged in); lab-gotest at b75c677d of relay-tcp and reality lab 2 × off and active prober: relay-tcp fails as expected, flagged on the tell over a short baseline (8 dials in 5.53 s of probes, 1 in 1.12 s outside); reality not judged (unattributable, 8 in 5.53 s against 8 in 8.12 s). No full lab: the brief asked for none, and only TestCensorMatrix's scoring and the prober's text constants changed
- 2026-11-19 not verified: a long baseline past about 11 s (setup much slower than in any run so far) would read pass; see Notes
- 2026-11-19 in-progress → review
- 2026-11-19 review round 1: nits R1.1–R1.3, merge
- 2026-11-19 R1.1 mutation, killed: unjudged without the accept-only filter (TestUnjudged, "a flag-mode block over a short baseline")
