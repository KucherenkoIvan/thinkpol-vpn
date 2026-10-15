---
id: TP-070
title: "udp replay memory vs sender clock skew"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: S
depends_on: []
refs: [C1, C3, C6, DESIGN#transports]
owner: ""
branch: ""
---

## Goal
Replay filtering and sender-id memory use consistent clocks so a skewed sender cannot replay after eviction.

## Scope
- `udp/replay.go:110-119` forgets an evicted sender id after `maxClockSkew` on the receiver's clock; `wire.go:232-235` accepts a datagram within `maxClockSkew` of its sealed time on the sender's clock. Remember evicted and retired ids for twice the skew (or equivalent fix).
- `udp/listener.go:264-266`: a late datagram from a dead port can open a new link toward that address.
- `udp/replay.go:172`: a replay refreshes a slot's LRU stamp before the replay check.

## Out of scope
- Supervisor-restart replay window (TP-069).

## Acceptance
- [ ] evicted sender ids stay refused long enough relative to sender-clock acceptance
- [ ] `TestNineRedialsThenQuietThenOldest` extended with the sender's clock skewed ahead by the allowed skew (passive tap replay cannot open a link and get probe replies)
- [ ] a late datagram from a dead port does not open a new link toward that address (`udp/listener.go:264-266`)
- [ ] a replay does not refresh a slot's LRU stamp before the replay check (`udp/replay.go:172`)

## Notes
- **Independent review (2026-10-15):** failure scenario — sender clocked ahead by the allowed skew plus eight redials during an outage lets a passive tap replay a datagram, open a link to the attacker's address, and get probe replies. `TestNineRedialsThenQuietThenOldest` never skewed the sender's clock.

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 docs (backlog grooming): acceptance for listener and LRU-stamp bugs
