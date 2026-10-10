---
id: TP-006
title: "Path layer and relay protocol"
milestone: M0
area: dataplane/path
repo: thinkpol-vpn
size: L
depends_on: [TP-003, TP-005]
refs: [N2, DESIGN#data-plane]
owner: "agent-tp-006"
branch: "tp-006-path-layer-relay"
---

## Goal
WireGuard sees one stable endpoint per peer, while underneath packets travel over relay paths; server nodes forward opaque packets for others.

## Scope
- A WireGuard `conn.Bind`: the endpoint is a peer's node id; each peer has a set of candidate paths, named by their first hop (`netmap.Peer.Paths`: an adjacent relay, or the peer itself for a direct link), in priority order, built to hold several.
- Relay framing: header {destination node id, hop limit}, WireGuard payload untouched. A relay forwards by destination through its forwarding table (`netmap.Section.Routes`: destination → adjacent next hops, in priority order) and never decrypts; no node holds a whole path.
- Forwarding loop on server nodes with per-link queues; drop on exhausted hop limit or unknown destination.
- Path selection: a single path for now, behind the interface the scoring in TP-031 will use.

## Out of scope
Multi-relay chains and hop groups (TP-030, TP-031), direct paths (later).

## Acceptance
- [ ] in-process test with three nodes over an in-memory transport: A → relay → B delivers
- [ ] a relay refuses destinations its section doesn't list
- [ ] no packet is ever sent through a WireGuard-owned UDP socket

## Notes
- From TP-003's review: `netmap`'s reader (`(*Map).Open`) checks only that a section is well formed. It accepts what only `netmap.Build` rejects: repeated or overlapping overlay addresses, addresses outside the overlay, empty `Paths`, `NextHops` or `Endpoints`, invalid (zero) `netip.AddrPort`s, and routing loops across several nodes. Don't assume them away: give relayed packets a hop limit and drop at zero (loops across nodes are possible), skip paths and routes with no usable hop, and check an endpoint's `AddrPort` is valid before dialing.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): destination routing — candidate first hops on the sender, a forwarding table per relay
- 2026-10-10 docs (TP-003 review): notes on what the map reader does not guarantee
- 2026-10-10 backlog → in-progress — owner: agent-tp-006, branch: tp-006-path-layer-relay
