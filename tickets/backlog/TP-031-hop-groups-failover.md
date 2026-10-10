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
- [ ] paths are probed end to end (each candidate first hop through to the peer), replacing TP-006's E2EDead stopgap; a path broken beyond its first hop is left within the failover bound

## Notes
- From TP-006: policies plug in as `path.Selector`s (`Peer.Selector` for first hops, `Route.Selector` for next hops in the middle); `Candidate` carries `Up`, `UpFor`, `RTT`, `HeardVia`, `Followed`. A stateful selector must be passed again, the same value, on every SetPeers/Update. One end of each pair follows (the higher node id); relays in the middle follow per destination when the destination leads. `spread` in the middle of a chain needs per-(source, destination) state that `Select(current, cands)` doesn't express yet.
- TP-006's end-to-end liveness is a stopgap: a Bind demotes a first hop after `E2EDead` (5 s) of unanswered handshakes, or E2EDead + 10 s of unanswered data, or E2EDead while the peer talks through another hop (leader). End-to-end probes over each path (a new frame kind; older nodes drop unknown kinds) should replace it; see the acceptance item. The TP-006 policy pinned by `TestAFailedOverPairReturnsAfterTheHoldDown`: a failed-over pair stays on the backup for the hold-down, then the leader returns to the primary and the follower comes along; this ticket decides the final policy (and whether a dialed link returns to its first endpoint).
- `Bind.Current` and `Node.Route` give the current entry and next hop, with since when, for the local API status.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): hop groups map onto first hops and route next hops
- 2026-10-10 docs (TP-006 review): notes from the path layer
