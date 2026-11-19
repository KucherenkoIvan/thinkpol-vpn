---
id: TP-247
title: "The censor matrix's slow rows split across labs so the default stream fits its budget"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: [TP-239, TP-241, TP-236]
refs: []
owner: "agent-tp-247"
branch: "tp-247-split-matrix-rows"
---

## Goal
The owner wants a full lab to take at most 15 minutes on the remote runner (2026-11-16); after the lab-speed tickets the default stream still took ~36 minutes (TP-239's measurement, 2026-11-19). Since TP-240 each transport row runs its cells one after another in one lab; the reality row's cells take ~8m19s even without the rhythm hold (TP-239's budget report), which alone rules out 15 minutes.

## Scope
- Measure each row's serial time from the budget report.
- Split the slowest rows into 2–3 labs (or run independent cells of a row in parallel where they don't share state), trading a few container starts for wall time.
- Keep every reset check (TP-240) and every verdict identical.

## Out of scope

## Acceptance
- [ ] The matrix's longest default-stream lab ≤ 5 minutes. Evidence: the budget report.
- [ ] RESULTS.md verdicts identical to the per-row run (diff).
- [ ] Container starts added, in Notes.

## Notes

## Log
- 2026-11-19 created in backlog (lab-speed follow-ups)
- 2026-11-19 backlog → in-progress, owner: agent-tp-247
