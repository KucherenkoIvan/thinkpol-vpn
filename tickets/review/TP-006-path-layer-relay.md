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
- [x] in-process test with three nodes over an in-memory transport: A → relay → B delivers — `TestRelayDelivers` (raw Bind traffic both ways; the relay counts 2 forwarded, 0 delivered; WireGuard sees the same endpoint for B both ways) and `TestWireGuardThroughARelay` (two real wireguard-go devices, `tuntest` TUNs, ping both ways through the relay; WireGuard reports no listen port and B's node id as its endpoint). Both on `memory.Datagram` and `memory.Stream`. Failover: `TestSwitchesPathWhenTheFirstHopGoesSilent` (wall clock: R1 goes silent with no error, as a dead udp peer does; both ends move to R2 within one DeadAfter), `TestSwitchTimingOnTheFakeClock` (the switch comes between DeadAfter − ProbeInterval and DeadAfter after the silence, not before), `TestSwitchesPathWhenTheRelayCloses`, `TestWireGuardSessionSurvivesAPathSwitch` (real devices, R1 silenced, pings resume through R2, `last_handshake_time` unchanged: same session). Pairs: `TestTheFollowerConvergesOnTheLeadersPath` (ends starting on different hops converge on the leader's and never switch again over 20 rounds), `TestTheFollowerTakesTheLeadersPath`, `TestAFailedOverPairReturnsAfterTheHoldDown`, `TestTheLeaderLeavesAHopTheFollowerCantUse`. End to end: `TestUnansweredHandshakesDemoteAFirstHop` (switches at E2EDead, back after E2EDead + hold-down, demoted again for twice as long), `TestUnansweredDataDemotesAFirstHopLater` (E2EDead + 10 s). Middle of a chain: `TestMidChainRelayFollowsTheLeadingEnd`. Loops: `TestHopLimitEndsRoutingLoops` (three relays routing B in a circle: exactly 7 forwards then one hop-limit drop, also for a packet arriving with hop limit 255). `go test -race -count=30` on `internal/dataplane/path` and `internal/dataplane` passes
- [x] a relay refuses destinations its section doesn't list — `TestRelayRefusesDestinationsNotInItsTable`: the relay has a route to A but not to B, though B is adjacent; A → B is dropped (`NoRoute` 1, B gets nothing), B → A is forwarded. `TestEndpointsDropWhatIsNotForThem`: a node with no routes drops a packet for another node (`NoRoute`) and one from a node no Bind has as a peer (`UnknownPeer`). `TestRelaysCheckTheSourceByReversePath`: a neighbor claiming another node's source is dropped at the relay and at the destination (`Spoofed`). `TestFramesOnTheLink`: frames spoken by hand. `TestPathConfigSkipsWhatItCannotUse`: routes to self or with no adjacent next hop never reach the table
- [x] no packet is ever sent through a WireGuard-owned UDP socket — the Bind's `Open` reports port 0 and WireGuard reports no `listen_port` (`TestWireGuardThroughARelay`); `ParseEndpoint` refuses anything but a node id and `SetMark` refuses marks (`TestBindContract`), so WireGuard can't be pointed at an address or given a socket option; a forbidigo rule scoped to `internal/dataplane/path` bans `net.Dial*`/`Listen*`/`File*Conn`, `net.Dialer`, `ListenConfig`, `UDPConn`/`TCPConn`/`IPConn`/`UnixConn`, wireguard-go's std binds and `syscall`/`unix`/`windows` (checked once with a throwaway file: two hits in `path`, none in `wg`); `TestNoSocketsInThePathLayer` checks the same in `make test`

## Notes
**API** (`internal/dataplane/path`, contract in `doc.go`):
- `NewNode(id NodeID, Options) (*Node, error)`; `(*Node).Update(Table)`, `Serve(transportName string, transport.Listener) error` (blocks; nil when the node closed first), `NewBind() *Bind`, `SetPeers(map[*Bind][]Peer) error` (several Binds in one step: peer moves), `Counters() Counters`, `Neighbors() []NeighborStatus` (with `Links []LinkStatus`), `Route(dst) (hop, since, ok)`, `ID()`, `Close()`. `NodeID = transport.NodeID` (`path.NodeID(netmapID)` converts).
- `Options{ProbeInterval, DeadAfter, FollowFor, E2EDead, RedialMin, RedialMax, HopLimit, QueueLen, Selector, Space, Now}`; NewNode refuses DeadAfter ≤ ProbeInterval, RedialMax < RedialMin and the zero id.
- `Table{Links []Link{Node, Endpoints []Endpoint{Transport, Dialer, Address, Config}}, Routes []Route{Destination, NextHops, Selector}}`. `Update` keeps links whose endpoints didn't change (dialers of types `==` can't compare are always redialed), keeps route state for routes that stay, and skips zero ids, self references, duplicate hops and empty routes. Endpoint priority applies on (re)dial only: a link carries on through the endpoint it got, and the first endpoint is tried again only once that link dies (TP-031 may add return-to-primary).
- `Bind` implements `conn.Bind`: `SetPeers([]Peer{ID, FirstHops, Selector})`, `Release()` (peers freed, Bind off the node), `Current(peer) (hop, since, ok)`, `Open` (port 0), `Close`, `Send`, `ParseEndpoint` (16 hex chars of a node id, nothing else), `BatchSize` 16, `SetMark` (`ErrNoSocket` for any non-zero mark). Errors `ErrUnknownPeer`, `ErrNoPath`, `ErrPeerTaken`, `ErrReleased`, `ErrMessageSize`, `ErrNoSocket`.
- `Selector{Select(current NodeID, cands []Candidate) (NodeID, bool)}`; `Candidate{Hop, Up, UpFor, Linked, RTT, HeardVia, Followed}`; `Failover{HoldDown}`. The path layer keeps only `current`: a selector with state of its own must be passed again, the same value, on every SetPeers/Update that keeps the peer or route.
- `MessageBudget(mtu, ipHeaders, transportOverhead int) int`, `HeaderSize`, `MaxMessageSize`, `DefaultHopLimit`.
- Status holds no network addresses (it may go into telemetry): `LinkStatus{Dialed, Transport, Endpoint (index, −1 accepted), Active, Up, UpFor, RTT, PacketsIn/Out, BytesIn/Out, QueueFull}`.
- Engine conversion: `dataplane.PathConfigFrom(netmap.Section, *transport.Registry) PathConfig{Table, Peers, Skipped []error}` (`internal/dataplane/paths.go`) applies TP-003's reader caveats: unknown transports, invalid/zero-port/unspecified `AddrPort`s and endpoints the transport's `CheckEndpoint` refuses are skipped; first and next hops must be adjacent (a `Link` or an `Inbound` peer) and not self; routes left without a next hop are dropped; peers without a usable first hop stay, with none. It fills `Endpoint.Transport`.

**Relay header** (inside the transport's seal, never on the wire; `frame.go`):
```
packet:      kind=1 | hop limit [1] | destination [8] | source [8] | WireGuard message   (HeaderSize = 18)
probe:       kind=2 | 0 [1] | token [8]
probe reply: kind=3 | 0 [1] | token [8]
```
- **Source id** (DESIGN said {destination, hop limit}): it tells the destination's path layer which peer, and so which WireGuard device, a packet is for, and gives WireGuard an endpoint it can answer (without it, WireGuard's roaming would set an unusable endpoint; `DisableSomeRoamingForBrokenMobileSemantics` is a device-wide quirk that also loses cookie replies). Relays check it by reverse path: a packet must come from its source or from a next hop of the route back to its source; at the destination it must come through one of the peer's first hops. Otherwise `Spoofed`. DESIGN.md says so.
- Hop limit: senders start at `DefaultHopLimit` 8; a relay caps what arrives at its own `HopLimit`, forwards with one less, and drops a packet that would arrive with 0 (frames arriving with 0 are malformed), so a loop costs at most 7 forwards whatever a neighbor claims. Relays never send a packet back to the neighbor it came from (split horizon).
- Probe tokens are random; a link remembers its last 8 outstanding probes and a reply counts for the RTT only if it matches one (once). Every frame received counts for liveness.
- Unknown kinds are dropped, so new kinds (TP-031's end-to-end probes) are ignored by older nodes. `MaxMessageSize` = 8192 − 18.

**Liveness and selection** (defaults; all in `Options`):
- **First hop.** Only the dialing end probes: when a link hasn't both sent and received within `ProbeInterval` 2 s. The other end answers and hears from a live dialer at least that often. A link silent for `DeadAfter` 6 s is down and closed; a dialed one is redialed (`RedialMin` 250 ms doubling to `RedialMax` 5 s while dials never hear back). Accepted links count as up from Accept. Every `Link` in the table is dialed, so backups are warm. Traffic to a neighbor stays on its active link while that link is up. Failover bound for a dead first hop: DeadAfter + a quarter probe interval ≈ 6.5 s.
- **Beyond the first hop (stopgap).** A Bind demotes its current first hop for a peer when, since the last answer, it has sent handshake initiations through it for over `E2EDead` 5 s (WireGuard's first retry, 5–5.33 s after the initiation, already takes the next hop), or anything for over E2EDead + 10 s (WireGuard's keepalive timeout: a peer that only receives answers no sooner), or — for the leading end — anything for over E2EDead while the peer is talking through another hop. An answer is a WireGuard-shaped message other than a cookie reply: from the peer through any hop for a follower, through the current hop for a leader. A demoted hop is down for the peer for E2EDead, doubling (up to 64×) on each demotion within ten minutes; then a Failover leader returns to it only after the hold-down. The orchestrator's "~6 s" became 5 s so the first WireGuard retry already moves; data-only got the keepalive allowance because 6 s alone demotes healthy one-way flows. End-to-end probing of each path is TP-031's (added there as an acceptance item).
- **Pairs.** Exactly one end of each pair follows: the higher node id. `Failover`: (1) the hop the far end's traffic comes through, if this end follows, it is up here, and it was heard within `FollowFor`; (2) the current hop while up, replaced by an earlier one once that has been up for `HoldDown` 20 s; (3) the first up hop; (4) the first hop with any link. The leader returns to its primary after the hold-down and the follower comes along. Pinned by `TestAFailedOverPairReturnsAfterTheHoldDown`. **Deviation from finding 5's wording:** with finding 2 in place a failed-over pair stays on the backup only for the hold-down, not until the backup fails; the test pins that (TP-031 decides the final policy).
- **Middle of a chain.** Each route keeps a current next hop and when packets from its destination last came through each next hop (`HeardVia`). A relay follows the destination's path only when the destination is the lower id of the packet's (source, destination) pair, i.e. the leading end; otherwise it chooses by its own order and the destination follows. State is per destination, so flows from several sources share one choice.
- **Cookie replies** (type 3), which WireGuard sends to the endpoint of a packet it hasn't authenticated, go out by the selector without moving `current` or following; arriving ones don't refresh `HeardVia`/following or answer the e2e check, and neither does anything not shaped like a WireGuard message. **Residual:** shape is no proof. An adjacent node that may carry a peer's traffic (it passes the reverse-path check) can forge shaped junk to keep a hop looking answered or heard; it can also simply drop the traffic, which is the same power. WireGuard's own adoption of endpoints is authenticated, so following can't be steered by junk beyond `FollowFor` freshness of a hop WireGuard already adopted.
- **Known residual:** a follower that can't reach the leader's hop and talks through another is caught by the leader within E2EDead only while it talks; a silent follower is caught by the data rule (E2EDead + 10 s).

**For downstream tickets** (also written into their Notes):
- **TP-008:** one `NewNode` per space worker (`Options.Space` = the worker's space), `Update(PathConfigFrom(section, registry).Table)` on each map, `Serve(name, listener)` per listener; one `NewBind()` per WireGuard device; set all devices' peers with one `Node.SetPeers` call so a peer can move between devices; a peer key lives in exactly one device, and a chain's exit is a peer of that chain's device only; `Release` a Bind with its device. WireGuard peers get `endpoint=<node id hex>`, never a UDP address, no `listen_port`, never `fwmark` (`SetMark` refuses it, so `Up` fails loudly). MTU: `path.MessageBudget(outerMTU, 28|48, Transport.Overhead)`; TUN MTU = min over the node's links of that budget − 32 (WireGuard's data overhead): 1330 for a 1500-byte outer IPv6 path over udp. Refuse IPv6 on the overlay when the TUN MTU is below 1280 and surface it in status. Peers without first hops still go into WireGuard (Send fails with `ErrNoPath`).
- **TP-010:** the worker's Node `Serve`s the worker-side listener (`udp.Transport.ListenOn`, the `HandoffListener`) and refuses identities of another space (`OtherSpace`).
- **TP-011:** the composition root builds the transport `Registry` with the socket `Control` from TP-018 (`udp.New(udp.Options{Control})`).
- **TP-018:** links' sockets are marked by the transport (`udp.Options.Control`): Linux `SO_MARK` plus an `ip rule` sending marked traffic to the main table, Darwin `IP_BOUND_IF`/`IPV6_BOUND_IF`, Windows `IP_UNICAST_IF`. Never set `fwmark` on a WireGuard device.
- **TP-030:** multi-relay chains work by `Routes`, and every relay needs a route back to each source it carries (reverse-path check). The builder keeps first and next hops adjacent (or `PathConfigFrom` drops them) and computes a space-wide overlay MTU from the links' budgets.
- **TP-031:** policies plug in as `Selector`s (`Peer.Selector`, `Route.Selector`); `Candidate` carries `UpFor`, `RTT`, `HeardVia`, `Followed`. Acceptance item added there: end-to-end path probing (a new frame kind; old nodes drop unknown kinds) replaces the E2EDead stopgap. `spread` in the middle of a chain needs per-(source, destination) state that `Select(current, cands)` doesn't express yet. `Bind.Current` and `Node.Route` are the "current entry" for the local API status.

- From TP-003's review: `netmap`'s reader (`(*Map).Open`) checks only that a section is well formed. It accepts what only `netmap.Build` rejects: repeated or overlapping overlay addresses, addresses outside the overlay, empty `Paths`, `NextHops` or `Endpoints`, invalid (zero) `netip.AddrPort`s, and routing loops across several nodes. Don't assume them away: give relayed packets a hop limit and drop at zero (loops across nodes are possible), skip paths and routes with no usable hop, and check an endpoint's `AddrPort` is valid before dialing.

## Review findings
Two reviewers; orchestrator decisions to implement as stated.

Liveness / failover:
- [x] 1 Beyond-first-hop black hole: end-to-end stopgap in the Bind. Sending to a peer through hop H for longer than E2EDead (default ~6 s, tuned to WireGuard's 5 s handshake retry) with nothing from that peer delivered through any hop demotes H for that peer (treated as down) and the next first hop is tried; recovery per hold-down. Data-plane delivery counts as liveness, not only probes (size-selective drops). Correct Notes/DESIGN: the detection bound applies to first-hop failures, e2e here is a stopgap; full e2e probing goes to TP-031 as an explicit acceptance item
- [x] 2 Pair flapping: exactly one end of a pair follows: the lower node id leads (never follows), the higher follows. Test: ends starting on different hops converge without oscillation
- [x] 3 Mid-chain: per-destination route state with the same Selector machinery (hysteresis, following via heard-from), `Route{Destination, NextHops, Selector}`; split horizon kept. TP-031 note: `spread` in the middle needs per-(src, dst) state the Selector signature doesn't express yet
- [x] 4 Sticky link per neighbour: no per-packet alternation between two up links; prefer the active one while up
- [x] 5 `Candidate.HeardVia` (how long ago the peer's last packet came through Hop); document that stateful selectors must be reused across SetPeers; test pinning the TP-006 policy "a failed-over pair stays on the backup" (TP-031 decides the final policy)

Security:
- [x] 6 A relay caps the incoming hop limit at its own HopLimit; test with hops = 255 in a loop
- [x] 7 Reverse-path source check on relays and at the destination (`src == from || from ∈ routes[src]`; deliver drops when via isn't one of the peer's hops); `Spoofed` counter; fix the Candidate.Followed / "authenticated" wording
- [x] 8 Don't follow or update current from WireGuard cookie replies (type 3); refresh lastSeen only in ways unauthenticated junk can't drive, as far as practical; document the residual
- [x] 9 Random probe tokens, an outstanding-probe table, unmatched replies ignored
- [x] 10 `Options.Space`: Serve closes (and counts) accepted links whose identity is another space

Lifecycle / API:
- [x] 11 `Bind.Release()` (peers freed, Bind removed from the node), atomic peer moves between Binds if cheap; TP-008 note: one peer key per WireGuard device, chain exits live in the chain's device
- [x] 12 `SetMark` returns `ErrNoSocket` for non-zero marks; notes for TP-018 (socket marks via `udp.Options.Control`: Linux SO_MARK + ip rule, Darwin IP_BOUND_IF/IPV6_BOUND_IF, Windows IP_UNICAST_IF; never fwmark on the WireGuard device) and TP-011 (the composition root builds the Registry with that Control)
- [x] 13 Observability: `Endpoint.Transport` (registry name, filled by PathConfigFrom); per-link `LinkStatus` (dialed, transport, endpoint index, up, upFor, RTT, packets/bytes in/out, queue full) under NeighborStatus; `Bind.Current` returns (hop, since, ok). No addresses in status meant for telemetry
- [x] 14 MTU: `path.MessageBudget` helper; TP-008 note (TUN MTU = min over links; refuse IPv6 below 1280 and surface it in status); TP-030 note (the builder computes a space-wide overlay MTU)
- [x] 15 DESIGN wording for the source id: it selects the device/peer for the path layer and gives WireGuard an answerable endpoint; relays check it by reverse path

Tests / nits:
- [x] 16 `Options.Now` injectable clock; time-based tests assert ordering with the fake clock (keep one wall-clock NFR test); larger timeouts where wall clock remains
- [x] 17 `TestFailoverDoesNotFlap` can fail (primary sometimes stays up past the hold-down; assert timing)
- [x] 18 A forbidigo rule (or extended AST check) banning net.Dialer/ListenConfig/UDPConn/TCPConn/IPConn/UnixConn in internal/dataplane/path
- [x] 19 Prune neighbours no longer referenced after Update; `send()` checks `l.done`; Options validation (DeadAfter > ProbeInterval, RedialMax ≥ RedialMin); Dialer comparison safe for non-comparable types; Bind counters (over-long → Malformed, count at dequeue, deliver/Close race drained)
- [x] 20 Document that endpoint priority applies on redial only (TP-031 may add return-to-primary)

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): destination routing — candidate first hops on the sender, a forwarding table per relay
- 2026-10-10 docs (TP-003 review): notes on what the map reader does not guarantee
- 2026-10-10 backlog → in-progress — owner: agent-tp-006, branch: tp-006-path-layer-relay
- 2026-10-10 docs: DESIGN.md "Data plane" — the relay header also carries the source node id (WireGuard must know which peer a packet came from); links are probed for liveness and the far end follows a path switch
- 2026-10-10 in-progress → review — all acceptance checked; `make lint`, `make test` and `go test -race -count=30` on the path packages pass
- 2026-10-10 review → has-errors — two reviewers: 20 findings (see Review findings)
- 2026-10-10 has-errors → in-progress — owner: agent-tp-006, picking up the review findings
- 2026-10-10 merged origin/rewrite (TP-002, TP-007); review findings 1–20 fixed; DESIGN.md "Data plane": source id checked by reverse path, first-hop vs end-to-end liveness, one end of a pair follows; notes for TP-008, TP-011, TP-018, TP-030 and TP-031 written into their tickets
- 2026-10-10 in-progress → review — every finding checked; `make lint`, `make test` and `go test -race -count=30` on the path packages pass
