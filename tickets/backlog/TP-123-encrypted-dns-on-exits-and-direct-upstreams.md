---
id: TP-123
title: "Decide: encrypted DNS on exits and on direct upstreams"
milestone: M3
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: [TP-077]
refs: []
owner: ""
branch: ""
---

## Goal
A recorded decision on plain DNS: whether exits ask their public resolvers over DoT/DoH, and whether a device's direct upstreams are protected against an on-path attacker answering first. Then tickets for what is decided.

## Scope
- Today both are plain DNS (the residual-risks row "Plain DNS" from TP-077): an on-path attacker can answer a device's direct query first, and an exit's tunnel-bound queries cross the exit's network in the clear, seen by the public resolver as coming from the exit.
- Weigh DoT/DoH on exits (fingerprint of the exit's traffic, resolver choice, failure modes when the resolver blocks DoT), and what can be done for direct queries (they are direct by the user's preset; DoH there changes what the preset promises).
- Write the decision in DESIGN.md and PRD (R4/D6 wording), update the residual-risks row, and file the implementation tickets.

## Acceptance
- [ ] the decision and its reasons are in DESIGN.md; the residual-risks row names its owner ticket or says why it stays

## Notes
- From TP-077's residual-risks research (2026-10-22): "later" in DESIGN, no ticket.

## Log
- 2026-10-22 created in backlog (TP-077 out-of-scope note)
