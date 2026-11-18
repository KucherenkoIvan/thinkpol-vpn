---
id: TP-236
title: "Flaky censor-matrix cell udp × fully-encrypted after a mid-cell redial"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: agent-tp-236
branch: tp-236-udp-fe-flake
---

## Goal
In a full lab (TP-223's run, 2026-11-16) the censor-matrix cell `udp × fully-encrypted` came out partial (only IPv6 crossed) after the link redialed mid-cell; re-runs passed. Find why the redial happens mid-cell and make the cell's verdict not depend on it.

## Scope
- Reproduce, name why the link redials mid-cell, and fix the cause or the cell.

## Out of scope

## Acceptance
- [ ] The root cause named in Notes, with evidence.
- [ ] A fix.
- [ ] 20 runs of the cell under load pass, and a mutation that brings the cause back fails.
- [ ] No retries and no longer timeouts without a cause.

## Notes
- First seen in TP-223's full lab at 17b3b1f1 (its Log, 2026-11-16).
- Seen again in TP-240's per-row matrix run on 7d37478b (2026-11-17): in the cell `udp against fully-encrypted` the server's udp link came up 0.3 s before censord was ready, closed after 6 s (its probes dropped), and a new link then crossed over IPv6, so the cell scored partial, want fail. Every reset held. Candidates to check: the cell's transport starting before the censor is ready; the fully-encrypted module and IPv6 flows that start after a redial.

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
- 2026-11-18 Notes: evidence from TP-240's matrix run
- 2026-11-18 backlog → in-progress, owner: agent-tp-236
