---
id: TP-237
title: "reality hides WireGuard's handshake rhythm with cover records"
milestone: later
area: dataplane/transport/reality
stream: transports
repo: thinkpol-vpn
size: L
depends_on: [TP-223]
refs: [RR65, C6]
owner: ""
branch: ""
---

## Goal
TP-223's lab measured that a censor counting TLS records in each direction sees reality's WireGuard rekey: at each rekey the device sends 3 records and the server 2, so the per-connection count difference steps by +1 every ~120 s (at 124.5, 246.0 and 366.1 s in a 7.5-minute hold). Padding hides sizes but not counts or timing. Hide it with random cover records in both directions, so record counts and timing drift randomly instead of stepping on WireGuard's timers (owner, 2026-11-16).

## Scope
- A design note first (docs/design/, the transport shaping section), approved by the owner before any code: the cover-record scheme (rates, randomness, both directions), its bandwidth cost and bound, per-link configuration (C6: each transport owns its shaping), and what the lab must show.
- Then the implementation in the reality transport.

## Out of scope
- WireGuard's own timer values (fixed in wireguard-go).

## Acceptance
- [ ] The design note approved by the owner (marked "(owner, date)").
- [ ] With cover records on, the lab's record-count rule and per-tick rule (TP-223) don't flag reality in the busy and idle holds, while plain `udp` is still caught (the control).
- [ ] The bandwidth overhead measured in the lab and within the design's bound.
- [ ] RR65 narrowed to what remains.

## Notes
- Owner, 2026-11-16: "Real fix: random cover records in both directions … this as a new ticket".
- Browser-like shaping was scheduled after the MVP (owner, 2026-11-07); the owner sets this ticket's milestone.

## Log
- 2026-11-16 created in backlog (owner decisions on the M2 rhythm findings)
