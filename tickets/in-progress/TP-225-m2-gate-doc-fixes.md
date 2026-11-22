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
owner: "agent-tp-225"
branch: "tp-225-m2-gate-doc-fixes"
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
The orchestrator's per-item list for the macOS IPv6 box. The owner's proxy rule (2026-11-16): an IPv6 item counts as proven by proxy when it shares all the same logic as an IPv4 behaviour proven on a device.
- A. The macOS kill switch's IPv6 half: proven by proxy (its block rule is family-agnostic, `all`), except the IPv6-only housekeeping passes (DHCPv6, ND, MLD), which stay unproven; they fail toward breakage, not toward a leak. The device sitting adds a step: kill switch on, allow-LAN off, disconnected, `ping6` to the router's link-local address → refused.
- B. The macOS IPv6 guard (the pf anchor that blocks IPv6 when the tunnel has none): not proven by proxy: a different rule, table and anchor, and no cheap check on an IPv4-only network. RR15 narrows to exactly this: "the guard is unproven on a native-IPv6 network" (owner, 2026-11-17; the owner's phone hotspot has no IPv6, so no test there).
- C. The macOS route table's IPv6 routes: proven by proxy except RR16 and zoned (link-local, `%iface`) gateways. The device sitting adds a read-only `netstat -rn -f inet6` and `route get -inet6` step while connected and after the agent is killed.
- D1. Forwarded IPv6 (RR14): holds only if the sitting's S7 step runs, with the kill switch on and the guard absent.

## Log
- 2026-11-16 created in backlog (from the M2 gate review)
- 2026-11-22 backlog → in-progress, owner: agent-tp-225
