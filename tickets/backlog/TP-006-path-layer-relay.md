---
id: TP-006
title: "Path layer and relay protocol"
milestone: M0
area: dataplane/path
repo: thinkpol-vpn
size: L
depends_on: [TP-003, TP-005]
refs: [N2, DESIGN#data-plane]
owner: ""
branch: ""
---

## Goal
WireGuard sees one stable endpoint per peer, while underneath packets travel over relay paths; server nodes forward opaque packets for others.

## Scope
- A WireGuard `conn.Bind`: the endpoint is a peer's node id; each peer has a set of candidate paths (relay paths only for now, built to hold several).
- Relay framing: header {destination node id, hop limit}, WireGuard payload untouched; a relay forwards only to next hops its map section allows and never decrypts.
- Forwarding loop on server nodes with per-link queues; drop on exhausted hop limit or unknown destination.
- Path selection: a single path for now, behind the interface the scoring in TP-031 will use.

## Out of scope
Multi-relay chains and hop groups (TP-030, TP-031), direct paths (later).

## Acceptance
- [ ] in-process test with three nodes over an in-memory transport: A → relay → B delivers
- [ ] a relay refuses destinations its section doesn't list
- [ ] no packet is ever sent through a WireGuard-owned UDP socket

## Log
- 2026-10-10 created in backlog
