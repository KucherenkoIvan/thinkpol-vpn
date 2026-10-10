---
id: TP-027
title: "Transport shaping contract"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: M
depends_on: [TP-005]
refs: [C6, DESIGN#transports]
owner: "agent-tp-027"
branch: "tp-027-transport-shaping"
---

## Goal
Transports own traffic shape: padding, batching and timing are part of the transport contract, configured per link.

## Scope
- Shaping settings per link from the map: padding (none, to buckets, random range), batching window, timing jitter, idle cover traffic on/off.
- A reusable shaping layer transports can opt into; overhead metrics.
- Conservative defaults; tuning is lab work.

## Acceptance
- [ ] conformance suite extended with shaping cases
- [ ] padding visibly changes the packet-length distribution in a lab capture

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-027, branch: tp-027-transport-shaping
