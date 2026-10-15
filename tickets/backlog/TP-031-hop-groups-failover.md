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
- [ ] paths are probed end to end (each candidate first hop through to the peer), so a path broken beyond its first hop (or a relay's next hop) is left within the failover bound

## Notes
- Split before starting (backlog grooming 2026-10-15).
- From TP-006: policies plug in as `path.Selector`s (`Peer.Selector` for first hops, `Route.Selector` for next hops in the middle) over a `path.Choice{Current, Follows, Candidates}`; `Candidate` carries `Up`, `UpFor`, `RTT`, `HeardVia`, `Followed`. A stateful selector must be passed again, the same value, on every SetPeers/Update. One end of each pair follows (the higher node id) and never returns to its primary on its own; relays in the middle don't follow. `spread` in the middle of a chain needs per-(source, destination) state that `Choice` doesn't carry yet.
- **Liveness in M0–M2 is link liveness only** (TP-006, after its delta review): failover covers a node's own first-hop (or next-hop) link failing. A first or next hop whose links are up but that can't reach the peer further on goes unnoticed until this ticket's end-to-end probes (a new frame kind; older nodes drop unknown kinds); see the acceptance item. TP-006 tried an end-to-end demotion stopgap and removed it: without probes it demoted healthy hops across idle gaps. The policy pinned by `TestAFailedOverPairReturnsAfterTheHoldDown`: the leader returns to its primary after the hold-down and the follower comes along; this ticket decides the final policy (and whether a dialed link returns to its first endpoint).
- `Bind.Current` and `Node.Route` give the current entry and next hop, with since when, for the local API status.

## Notes
- **From TP-027:** probes and probe replies go through `transport.WriteControl`, which may hold them up to `transport.MaxControlHold` (500 ms) at each end: a probe round trip is an upper bound, good for liveness, not for `lowest-latency`. Compare latency on unheld traffic: WireGuard's handshake round trip (initiation → response through the Bind) or `WritePacket` probes on links without batching or jitter, or only beyond `2 × MaxControlHold` plus both ends' `Shaping.MaxDelay()`. Allow `2 × MaxControlHold` in probe timeouts; jitter the probe interval, skip probes on links that carried data recently, probe warm backups less often.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): hop groups map onto first hops and route next hops
- 2026-10-10 docs (TP-006 review): notes from the path layer
- 2026-10-15 docs (backlog grooming): split note
