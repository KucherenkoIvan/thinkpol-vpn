---
id: TP-195
title: "Health grades an exit by its WireGuard handshake"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-140]
refs: []
owner: ""
branch: ""
---

## Goal
Health is not "ok" while a peer the device routes through (an exit, directly or behind a relay) has never completed a WireGuard handshake or has gone silent past a deadline.

## Scope
Today health counts only neighbours (the first hop). Device → entry → exit with the entry up and the exit never answering reads ok, and so does a direct exit whose link is proven but whose handshake never completes. TP-140 recorded this in RESIDUAL-RISKS.md and its Notes.

## Out of scope
None named.

## Acceptance
- [ ] a unit test: an exit peer with no handshake past the deadline raises a problem (snake_case code); one that handshakes clears it
- [ ] lab: device → relay → exit with the exit's WireGuard blocked shows the problem in `thinkpol status`
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- From TP-140's round-1 reviews, 2026-11-07. On the MVP path (orchestrator's call): the tray and daily use read health.

## Log
- 2026-11-07 created in backlog

