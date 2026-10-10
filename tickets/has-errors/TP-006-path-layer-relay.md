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
- [x] in-process test with three nodes over an in-memory transport: A → relay → B delivers — `TestRelayDelivers` (raw Bind traffic both ways; the relay counts 2 forwarded, 0 delivered; WireGuard sees the same endpoint for B both ways) and `TestWireGuardThroughARelay` (two real wireguard-go devices, `tuntest` TUNs, ping both ways through the relay; WireGuard reports no listen port and B's node id as its endpoint). Both on `memory.Datagram` and `memory.Stream`. Beyond the box: `TestSwitchesPathWhenTheFirstHopGoesSilent` (R1 goes silent with no error, as a dead udp peer does; both ends move to R2 in ~143 ms with DeadAfter 150 ms), `TestSwitchesPathWhenTheRelayCloses`, `TestFollowsThePathThePeerUses` (only A loses R1: B's own choice R1 can't deliver, B answers through R2 by following the endpoint WireGuard adopted), `TestWireGuardSessionSurvivesAPathSwitch` (real devices, R1 silenced, pings resume through R2, `last_handshake_time` unchanged: same session), `TestHopLimitEndsRoutingLoops` (three relays routing B in a circle: exactly 7 forwards, then one hop-limit drop), `TestFramesOnTheLink` (frames spoken by hand: unknown kind, zero hops, no message and last-hop packets dropped; probes answered). `go test -race -count=30` on `internal/dataplane/path` and `internal/dataplane` passes
- [x] a relay refuses destinations its section doesn't list — `TestRelayRefusesDestinationsNotInItsTable`: the relay has a route to A but not to B, though B is adjacent; A → B is dropped (`NoRoute` 1, B gets nothing), B → A is forwarded. `TestEndpointsDropWhatIsNotForThem`: a node with no routes drops a packet for another node (`NoRoute`) and one from a node no Bind has as a peer (`UnknownPeer`). `TestPathConfigSkipsWhatItCannotUse`: routes to self or with no adjacent next hop never reach the table
- [x] no packet is ever sent through a WireGuard-owned UDP socket — the Bind's `Open` reports port 0 and WireGuard reports no `listen_port` (`TestWireGuardThroughARelay`); `ParseEndpoint` refuses anything but a node id (`127.0.0.1:51820`, `[::1]:51820`, …; `TestBindContract`), so WireGuard can't be pointed at an address; `TestNoSocketsInThePathLayer` parses the package's sources and fails on any socket call (`net.Dial*`, `net.Listen*`, `net.File*Conn`, `conn.NewDefaultBind`/`NewStdNetBind`) or a `syscall`/`x/sys` import

## Notes
**API** (`internal/dataplane/path`, contract in `doc.go`):
- `NewNode(id NodeID, Options) *Node`; `(*Node).Update(Table)`, `Serve(transport.Listener) error` (blocks; nil when the node closed first), `NewBind() *Bind`, `Counters() Counters`, `Neighbors() []NeighborStatus`, `ID()`, `Close()`. `NodeID = transport.NodeID` (`path.NodeID(netmapID)` converts).
- `Table{Links []Link{Node, Endpoints []Endpoint{Dialer, Address, Config transport.DialConfig}}, Routes []Route{Destination, NextHops}}`. `Update` keeps links whose endpoints didn't change and redials the rest; it skips zero ids, self references, duplicate hops and empty routes itself as well.
- `Bind` implements `conn.Bind`: `SetPeers([]Peer{ID, FirstHops, Selector}) error` (a peer belongs to one Bind: `ErrPeerTaken`), `Current(peer) (NodeID, bool)`, `Open` (port 0), `Close`, `Send`, `ParseEndpoint` (16 hex chars of a node id, nothing else), `BatchSize` 16, `SetMark` no-op. Errors `ErrUnknownPeer`, `ErrNoPath`, `ErrMessageSize`.
- `Selector{Select(current NodeID, cands []Candidate) (NodeID, bool)}`; `Candidate{Hop, Up, UpFor, Linked, RTT, Followed}`; `Failover{HoldDown}`.
- Engine conversion: `dataplane.PathConfigFrom(netmap.Section, *transport.Registry) PathConfig{Table, Peers, Skipped []error}` (`internal/dataplane/paths.go`), where DESIGN puts map → port conversions. It applies TP-003's reader caveats: unknown transports, invalid/zero-port/unspecified `AddrPort`s and endpoints the transport's `CheckEndpoint` refuses are skipped; first and next hops must be adjacent (a `Link` or an `Inbound` peer) and not self; routes left without a next hop are dropped; peers without a usable first hop stay, with none.

**Relay header** (inside the transport's seal, never on the wire; `frame.go`):
```
packet:      kind=1 | hop limit [1] | destination [8] | source [8] | WireGuard message   (HeaderSize = 18)
probe:       kind=2 | 0 [1] | token [8]
probe reply: kind=3 | 0 [1] | token [8]
```
- **Source id added** (DESIGN said {destination, hop limit}): the destination must tell WireGuard which peer a packet came from, or WireGuard's roaming would set the peer's endpoint to something unusable. The alternative, `DisableSomeRoamingForBrokenMobileSemantics`, is a device-wide quirk that would also lose cookie replies under load. Relays learn nothing new: the first relay sees the source on its link, later ones see the same ids as destinations of the replies. DESIGN.md updated.
- Hop limit: senders start at `DefaultHopLimit` 8; a relay forwards with one less and drops a packet that would arrive with 0 (frames arriving with 0 are malformed), so a loop costs at most 7 forwards. Relays also never send a packet back to the neighbor it came from (split horizon).
- Unknown kinds are dropped, so new frame kinds (TP-031's end-to-end probes) are ignored by older nodes. `MaxMessageSize` = 8192 − 18.

**Liveness and selection** (defaults; all in `Options`):
- Only the dialing end probes: when a link hasn't both sent and received within `ProbeInterval` 2 s. The other end answers and hears from a live dialer at least that often. A link silent for `DeadAfter` 6 s is down and closed; a dialed one is redialed through its endpoints in priority order (`RedialMin` 250 ms doubling to `RedialMax` 5 s while dials never hear back). Accepted links count as up from Accept (the listener authenticated them). Probe RTT is smoothed (1/8) per link. Every `Link` in the table is dialed, so backup first hops are warm.
- `Failover`: (1) the hop the peer's latest authenticated packets came through, if it is up here and fresh (`FollowFor`, default `DeadAfter`); (2) the current hop while up, replaced by an earlier one only after it has been up for `HoldDown` 20 s; (3) the first up hop; (4) the first hop with any link. Relays pick next hops simply: the first with an up link, else the first with any link, skipping the arrival neighbor.
- Following works because the endpoints a Bind hands WireGuard carry {peer, via first hop}, and WireGuard adopts an endpoint only from a packet it authenticated. `DstToString`/`DstToBytes` are the peer's id for every via, so cookies and the UAPI see one stable endpoint; `DstIP` is a per-peer stand-in in `100::/64` (RFC 6666 discard prefix) so WireGuard's handshake rate limiter keys per peer.
- Known limit: while both ends keep talking, following beats `HoldDown`, so a pair that failed over stays on the backup until it fails too (sticky, no flapping). TP-031 decides whether that is the policy or whether one end leads.
- Failover NFR with defaults: detection ≤ `DeadAfter` + a quarter probe interval (≈ 6.5 s), plus at most `FollowFor` (6 s) of the far end following a stale path: under 15 s.

**For downstream tickets:**
- **TP-008:** one `NewNode` per space worker, `Update(PathConfigFrom(section, registry).Table)` on each map, `Serve` each listener; one `NewBind()` per WireGuard device with `SetPeers` (the overlay device gets the device peers; a chain's device gets its exit). Configure each WireGuard peer with `endpoint=<node id hex>` and never a UDP address; don't set `listen_port`. Peers without first hops still go into WireGuard (Send fails with `ErrNoPath`). MTU budget: WireGuard message ≤ outer MTU − IP/UDP (28 v4, 48 v6) − `Transport.Overhead` (udp 72) − `path.HeaderSize` 18; TUN MTU is that minus WireGuard's 32 (header and tag): 1330 for a 1500-byte outer IPv6 path over udp. `golang.zx2c4.com/wireguard` is now a non-test dependency (conn), and builds for Android.
- **TP-010:** a worker's path Node `Serve`s the worker-side listener (`udp.Transport.ListenOn`, the `HandoffListener`); the Identity's node id is the adjacent node, its space is ignored by the path layer (one Node per space).
- **TP-030:** multi-relay chains already work by `Routes` (tested with a loop of three relays); the builder must keep first hops and next hops adjacent, or `PathConfigFrom` drops them.
- **TP-031:** plug policies in as `Selector`s (per peer via `Peer.Selector`); `Candidate` already carries `UpFor`, `RTT` and `Followed`. End-to-end path probes need a new frame kind (old nodes drop unknown kinds). Relay next-hop choice for hop groups in the middle is in `Node.forward` and has no hysteresis yet. `Bind.Current` is the "current entry" for the local API status.

- From TP-003's review: `netmap`'s reader (`(*Map).Open`) checks only that a section is well formed. It accepts what only `netmap.Build` rejects: repeated or overlapping overlay addresses, addresses outside the overlay, empty `Paths`, `NextHops` or `Endpoints`, invalid (zero) `netip.AddrPort`s, and routing loops across several nodes. Don't assume them away: give relayed packets a hop limit and drop at zero (loops across nodes are possible), skip paths and routes with no usable hop, and check an endpoint's `AddrPort` is valid before dialing.

## Review findings
Two reviewers; orchestrator decisions to implement as stated.

Liveness / failover:
- [ ] 1 Beyond-first-hop black hole: end-to-end stopgap in the Bind. Sending to a peer through hop H for longer than E2EDead (default ~6 s, tuned to WireGuard's 5 s handshake retry) with nothing from that peer delivered through any hop demotes H for that peer (treated as down) and the next first hop is tried; recovery per hold-down. Data-plane delivery counts as liveness, not only probes (size-selective drops). Correct Notes/DESIGN: the detection bound applies to first-hop failures, e2e here is a stopgap; full e2e probing goes to TP-031 as an explicit acceptance item
- [ ] 2 Pair flapping: exactly one end of a pair follows: the lower node id leads (never follows), the higher follows. Test: ends starting on different hops converge without oscillation
- [ ] 3 Mid-chain: per-destination route state with the same Selector machinery (hysteresis, following via heard-from), `Route{Destination, NextHops, Selector}`; split horizon kept. TP-031 note: `spread` in the middle needs per-(src, dst) state the Selector signature doesn't express yet
- [ ] 4 Sticky link per neighbour: no per-packet alternation between two up links; prefer the active one while up
- [ ] 5 `Candidate.HeardVia` (how long ago the peer's last packet came through Hop); document that stateful selectors must be reused across SetPeers; test pinning the TP-006 policy "a failed-over pair stays on the backup" (TP-031 decides the final policy)

Security:
- [ ] 6 A relay caps the incoming hop limit at its own HopLimit; test with hops = 255 in a loop
- [ ] 7 Reverse-path source check on relays and at the destination (`src == from || from ∈ routes[src]`; deliver drops when via isn't one of the peer's hops); `Spoofed` counter; fix the Candidate.Followed / "authenticated" wording
- [ ] 8 Don't follow or update current from WireGuard cookie replies (type 3); refresh lastSeen only in ways unauthenticated junk can't drive, as far as practical; document the residual
- [ ] 9 Random probe tokens, an outstanding-probe table, unmatched replies ignored
- [ ] 10 `Options.Space`: Serve closes (and counts) accepted links whose identity is another space

Lifecycle / API:
- [ ] 11 `Bind.Release()` (peers freed, Bind removed from the node), atomic peer moves between Binds if cheap; TP-008 note: one peer key per WireGuard device, chain exits live in the chain's device
- [ ] 12 `SetMark` returns `ErrNoSocket` for non-zero marks; notes for TP-018 (socket marks via `udp.Options.Control`: Linux SO_MARK + ip rule, Darwin IP_BOUND_IF/IPV6_BOUND_IF, Windows IP_UNICAST_IF; never fwmark on the WireGuard device) and TP-011 (the composition root builds the Registry with that Control)
- [ ] 13 Observability: `Endpoint.Transport` (registry name, filled by PathConfigFrom); per-link `LinkStatus` (dialed, transport, endpoint index, up, upFor, RTT, packets/bytes in/out, queue full) under NeighborStatus; `Bind.Current` returns (hop, since, ok). No addresses in status meant for telemetry
- [ ] 14 MTU: `path.MessageBudget` helper; TP-008 note (TUN MTU = min over links; refuse IPv6 below 1280 and surface it in status); TP-030 note (the builder computes a space-wide overlay MTU)
- [ ] 15 DESIGN wording for the source id: it selects the device/peer for the path layer and gives WireGuard an answerable endpoint; relays check it by reverse path

Tests / nits:
- [ ] 16 `Options.Now` injectable clock; time-based tests assert ordering with the fake clock (keep one wall-clock NFR test); larger timeouts where wall clock remains
- [ ] 17 `TestFailoverDoesNotFlap` can fail (primary sometimes stays up past the hold-down; assert timing)
- [ ] 18 A forbidigo rule (or extended AST check) banning net.Dialer/ListenConfig/UDPConn/TCPConn/IPConn/UnixConn in internal/dataplane/path
- [ ] 19 Prune neighbours no longer referenced after Update; `send()` checks `l.done`; Options validation (DeadAfter > ProbeInterval, RedialMax ≥ RedialMin); Dialer comparison safe for non-comparable types; Bind counters (over-long → Malformed, count at dequeue, deliver/Close race drained)
- [ ] 20 Document that endpoint priority applies on redial only (TP-031 may add return-to-primary)

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): destination routing — candidate first hops on the sender, a forwarding table per relay
- 2026-10-10 docs (TP-003 review): notes on what the map reader does not guarantee
- 2026-10-10 backlog → in-progress — owner: agent-tp-006, branch: tp-006-path-layer-relay
- 2026-10-10 docs: DESIGN.md "Data plane" — the relay header also carries the source node id (WireGuard must know which peer a packet came from); links are probed for liveness and the far end follows a path switch
- 2026-10-10 in-progress → review — all acceptance checked; `make lint`, `make test` and `go test -race -count=30` on the path packages pass
- 2026-10-10 review → has-errors — two reviewers: 20 findings (see Review findings)
