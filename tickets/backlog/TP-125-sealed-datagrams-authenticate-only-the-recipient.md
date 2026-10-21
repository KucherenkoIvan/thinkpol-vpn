---
id: TP-125
title: "Decide: sealed datagrams authenticate only the recipient"
milestone: M2
area: transport
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
A recorded decision on the independent design review's point (2026-10-13, section 8) that `udp`'s sealed datagrams authenticate only the recipient, which TP-062 left undecided.

## Scope
- State what the point means for this design: who can produce a datagram the supervisor accepts, what the worker then trusts it for (WireGuard still authenticates the peer), and what an attacker gains (reply addresses, flow cost, fair share).
- Decide: accept (with the reason, and a residual-risks row if anything is left), or a change to the seal (sender authentication) with its cost.
- Write it in DESIGN.md (or the `udp` package doc for the mechanism) and file implementation tickets if any.

## Acceptance
- [ ] the decision and its reasons are written down; a residual-risks row exists if anything is accepted

## Notes
- From TP-077's residual-risks research (2026-10-22). TP-062's Notes: "not among the owner's decisions and isn't written down".

## Log
- 2026-10-22 created in backlog (TP-077 out-of-scope note)
