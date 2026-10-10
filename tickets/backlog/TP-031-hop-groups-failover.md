---
id: TP-031
title: "Hop groups and failover"
milestone: M3
area: dataplane/path
repo: thinkpol-vpn
size: L
depends_on: [TP-030]
refs: [R6, R7, DESIGN#data-plane]
owner: ""
branch: ""
---

## Goal
A chain hop can be a group of nodes; the client picks a healthy one and switches without breaking connections.

## Scope
- Hop groups in the map: at the start of a chain, a device's candidate first hops (`netmap.Peer.Paths`); in the middle, a relay's next hops (`netmap.Route.NextHops`). Both lists are in priority order, which `failover` follows; other policies may need a policy field next to them.
- Path scoring from probes over each path (handshake success, loss, RTT); failover with hysteresis.
- `failover` (must), `lowest-latency` and `spread` (should).
- Entry switches keep the WireGuard session with the exit; current entry exposed in the local API status.

## Acceptance
- [ ] killing the active entry moves traffic within 15 s and an open TCP connection survives
- [ ] no flapping under injected jitter

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): hop groups map onto first hops and route next hops
