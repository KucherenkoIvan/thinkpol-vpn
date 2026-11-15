---
id: TP-226
title: "A reality key per space (RR64)"
milestone: later
area: dataplane/transport/reality
stream: transports
repo: thinkpol-vpn
size: M
depends_on: []
refs: [RR64]
owner: ""
branch: ""
---

## Goal
Close RR64: today every space's worker behind a shared `reality` listener holds the listener's X25519 private key, so one guest space's worker taken over exposes every space's hellos on that listener.

## Scope
- Give each space its own key. RR64's Mitigation column says that takes a listener (an address or port) per space: design the cheapest way that keeps one public listener if possible, or accept the listener per space.

## Out of scope

## Acceptance
- [ ] A design note section (docs/design/) with the chosen shape, reviewed before code.
- [ ] No space's worker holds another space's key; a lab test proves it.
- [ ] RR64 closed or narrowed.

## Notes
- Matters once a node shares its listener with guest spaces (M4's shared nodes).
- Milestone set by the owner later (owner, 2026-11-16: file it).

## Log
- 2026-11-16 created in backlog (from the M2 gate review)
