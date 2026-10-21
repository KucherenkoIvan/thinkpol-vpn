---
id: TP-127
title: "IPv6 guard: a failed shrink of the direct set still narrows the guard"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: []
refs: [DESIGN#routing-rules-and-dns]
owner: ""
branch: ""
---

## Goal
When a smaller direct set fails to apply, and so does the fallback to nothing direct, IPv6 to the dropped prefixes is refused instead of going direct.

## Scope
- Today the guard is held to the routes still in place (`routetable` doc, "the guard follows the routes"). That is right when the new guard would be *wider* than the routes. When the new direct set is a *subset* of the old one, a narrower guard can only block, never leak. So on a failed shrink, apply the guard for the new direct set while the routes stay the old ones.
- IPv4 to the dropped prefixes keeps going direct until an Apply works. That part stays with the kill switch (TP-048).
- Health keeps saying the routes failed. Once this lands, the residual-risks row for a failed shrink (TP-077's RESIDUAL-RISKS.md) drops D6 and names this ticket for IPv6.

## Acceptance
- [ ] a test where removing direct prefixes fails and so does the fallback: the guard installed is the new, narrower set's, and the routes are the old ones. Mutation: holding the guard to the old routes fails it
- [ ] a test that a failed *grow* still holds the guard to the routes in place (no wider guard than the routes)
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- From TP-077's round-2 design review (2026-10-22): the row had no ticket. It breaks D6 (a must), and the subset case allows a fail-closed fix.

## Log
- 2026-10-22 created in backlog (TP-077 review round 2)
