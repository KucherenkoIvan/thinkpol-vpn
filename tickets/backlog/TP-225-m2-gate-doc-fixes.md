---
id: TP-225
title: "M2 gate doc fixes"
milestone: M2
area: docs
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-223]
refs: [C3, RR59, RR61, RR64, RR65]
owner: ""
branch: ""
---

## Goal
Make the requirement and design docs say what M2 actually delivers, as the M2 gate review found.

## Scope
- The doc changes listed under Acceptance.

## Out of scope

## Acceptance
- [ ] PRD C3: transport chosen per link in the map, and a map change applies without reinstalling (M2); "changeable from the panel" moves to the panel requirement at M4 (owner, 2026-11-16).
- [ ] PRD success metric 1: `reality` passes everything except whitelist mode, a block of the entry's own address, and a block of its camouflage name (owner, 2026-11-16).
- [ ] DESIGN.md (the firewall described as "later the kill switch"), docs/design/routing.md (interface-bound IPv4 said to wait for the kill switch) and docs/design/api-overview.md (summary: flags/env only, no config file, command count; the TP-141 row's schema version) match the code at head.
- [ ] RESIDUAL-RISKS.md: a new row: blocking `reality`'s camouflage name blocks `reality` on that entry (mitigation: choose a camouflage site the censor can't afford to block; several entries from M3) (owner, 2026-11-16).
- [ ] RESIDUAL-RISKS.md: RR59 points to TP-207, RR61 to TP-206, RR64 to TP-226; RR65 updated from TP-223's measurement.
- [ ] The macOS IPv6 rows (RR15 and others), PRD D6's macOS note and the M1 row's "not proven on a device yet" updated per the owner's proxy rule (an IPv6 item counts as proven by proxy when it shares all the same logic as an IPv4 behaviour proven on a device); the orchestrator adds the per-item list to Notes before this ticket starts.
- [ ] Every requirement-doc change carries "(owner, 2026-11-16)".

## Notes

## Log
- 2026-11-16 created in backlog (from the M2 gate review)
