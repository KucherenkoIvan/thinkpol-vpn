---
id: TP-029
title: "M2 acceptance"
milestone: M2
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-025, TP-026, TP-087]
refs: [C1, C2, C4]
owner: ""
branch: ""
---

## Goal
M2's "done when": the matrix shows `udp` getting caught and `reality` passing.

## Scope
- Run the full matrix; `reality` passes every M2 module; `udp`'s failures recorded (expected: the fully-encrypted heuristics).

## Acceptance
- [ ] `lab/RESULTS.md` committed with the M2 matrix

## Log
- 2026-10-10 created in backlog
- 2026-10-15 deps (board op): TP-028 → TP-087, `reality` is the M2 disguised transport
- 2026-10-15 docs (board op): Goal and Scope say `reality` instead of `tls`
