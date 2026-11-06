---
id: TP-184
title: "Bandwidth cap per guest space and fair share on a shared node"
milestone: M4
area: features/hosting
repo: thinkpol-vpn
size: L
depends_on: [TP-040]
refs: [N7, docs/design/server-agent.md#server-agent-one-worker-per-space]
owner: ""
branch: ""
---

## Goal
On a shared node, the node owner sets a bandwidth cap for each guest space, and under load the spaces share the node fairly, so one space can't starve another (PRD N7 and the Isolation requirement).

## Scope
- The cap per guest space, set by the node owner in the hosting grant and carried in the owner's map.
- Fair share between spaces under load, in both directions, for datagrams and handed-over streams.
- The parked design notes in TP-040 (`supervisor.FairShare` as per-space token buckets, pacing and policing for streams, per-space egress caps on the veth) are the starting point.

## Out of scope
- Hosting grants and shared nodes themselves: TP-040.
- Tuned traffic shaping beyond a cap and a fair share: after the MVP (docs/design/milestones.md).

## Acceptance
- [ ] lab: a guest space sending as fast as it can stays at its cap, measured on the node's uplink in both directions
- [ ] lab: with two spaces saturating a shared node, each gets at least its fair share within a stated margin, and an open connection of the quieter space stays alive
- [ ] lab: a datagram flood and a handed-over stream are both held to the cap
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Source: MVP triage 2026-11-07 against PRD N7.
- TP-040 parked caps and fair share (author, 2026-10-15); this ticket takes them back onto the MVP path, since N7 is a must for M4.

## Log
- 2026-11-07 created in backlog (MVP triage against PRD N7)
