---
id: TP-188
title: "Censor module: WireGuard rhythm inside TLS"
milestone: M2
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-089]
refs: [C1, C4, C6, docs/design/milestones.md#milestones, docs/design/lab.md#censor-lab]
owner: ""
branch: ""
---

## Goal
The lab catches a TLS flow that carries WireGuard with its rhythm showing: the 2-minute rekey pair and the fixed-size keepalive records. It is one of the checks `reality` must pass at the M2 gate (docs/design/milestones.md).

## Scope
- A censor-lab module that reads a flow's record sizes and timing and flags the WireGuard rhythm: a handshake-sized pair of records every 2 minutes, and fixed-size keepalive records.
- Test traffic: `udp`-in-TLS-like flows with the rhythm, and the same traffic with the rhythm removed.
- A row for the module in the M2 acceptance matrix (TP-029).

## Out of scope
- Flow shape beyond the rhythm (packet-size distributions, burst patterns): not tested at M2 (owner, 2026-11-07).
- Shaping in any transport: C6, `reality` in TP-087.

## Acceptance
- [ ] `udp`-in-TLS-like test traffic with the rhythm is flagged
- [ ] the same traffic with the rhythm removed passes
- [ ] the module runs in the M2 acceptance matrix
- [ ] `make lint`, `make test` and the censor lab tests pass

## Notes
- If `reality` fails it with default settings, the fix is a minimal padding/batching default in the transport, not a full shaping module (owner, 2026-11-07).

## Log
- 2026-11-07 created in backlog
