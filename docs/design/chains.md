# thinkpol-vpn — Chains and hop groups design

Chains with hop groups and failover (M3: PRD R5–R7, N9, C4's JA3/JA4 and throttling): what a chain is in the map, what the builder refuses, how a device learns that a path past its first hop is broken, how it picks a path, why an entry switch keeps open connections, and how the lab proves it. The entry point is [DESIGN.md](../../DESIGN.md); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md), numbered as after TP-217 (so `reality`'s minimal padding is RR65).

This file builds on what is decided: destination routing, hop groups and ingress/egress ([overlay](overlay.md#data-plane-every-node-one-binary)); `chain:<name>` and "chains in use at the same time end at different exits" ([routing](routing.md#routing-rules-and-dns)); traffic shape belongs to the transport ([transports](transports.md)); the path layer's frames, liveness, leader and follower and `Failover` ([`path`](../../internal/dataplane/path/doc.go), TP-006); control writes and `MaxControlHold` (TP-027); exit health by WireGuard's handshake (TP-195, TP-212, RR48). The section [Moves to `path/doc.go` at M3-4](#moves-to-internaldataplanepathdocgo-at-m3-4) is mechanism, kept here only until that ticket moves it; the M3 plan goes once its tickets are filed.

**Constraint.** Nothing in M3 changes the kill switch, the firewall, DNS takeover, the route table or the service. One existing path is touched: `overlay_mtu` lowers a node's TUN MTU, and an MTU below 1280 sets `IPv6Off`, which drops the overlay's IPv6 routes (`routetable.go:212`). The builder therefore refuses an `overlay_mtu` below 576, and below 1280 while the space carries IPv6.

## The model

A chain is a named way out: one exit, reached through hops. In M3 a chain is either **a group straight to its exit** (`[ru-1 | ru-2] → nl-1`: the device's candidate first hops) or **a line of single relays** (`A → B → exit`). A group is not an object any node sees: it compiles into a device peer's candidate first hops (`netmap.Peer.Paths`) with a policy. The device leads: it picks a first hop by the policy from what each member **vouches** about its link to the exit, sends WireGuard's packets for the exit through it, and the exit follows the first hop the device's authenticated packets arrive by. WireGuard's session is with the exit, so an entry switch is only a gap to it, the exit's NAT and the connection.

**Why a group only directly before the exit.** A relay behind a group would pick its hop back toward the device by its own `Failover` over the group's members (`node.go:528-545`, no following), so after the device leaves a blackholed member the relay keeps replying into it. Relays answering a device through the neighbor its last packet came from (relay-follow) fixes that; it is later work (M3-L1, RR72), not M3.

## Chains in the map and the builder

**The map carries no group object.** New fields, each one an older reader may ignore without widening anything ([Rollout](#rollout-and-older-nodes)):

| Field | Where | Meaning |
|---|---|---|
| `policy` | `Peer` | `failover` (0, default), `lowest_latency`, `spread`; unknown reads as `failover`. No `Route` policy in M3: groups are never a relay's next hops |
| `follow` | `Peer` | `unset` (0: TP-006's id rule), `lead`, `follow`. The builder sets `lead` on a device's exit peer and `follow` on the exit's device peer, so a device leads its exits whatever the ids |
| `vouch` | `Peer` | Ask each first hop to vouch for its link to this peer. Set for a chain's exit when the exit and the members are `chains`-capable |
| `group` | `Peer` | The group's name, display only (status, events); checked by `CheckChainName` |
| `delay_bound` | `Path` | The most the transports along device → member → exit may hold a packet, both ways, ms: the sum of each link's `Shaping.MaxDelay()` at both ends |
| `overlay_mtu` | `Section` | The largest TUN MTU every path from this node to its peers carries |

**How the builder knows a node's version.** The map holds none (only `min_reader` and its own version), so the spec gets the smallest field that says it: devmap's node entry takes `capabilities: [chains]`, meaning the node answers vouch probes, honours `follow` and reads `overlay_mtu`. Absent means pre-M3 (open question 7). The controller later fills the same from capabilities nodes report (TP-183). With it:

- an exit without `chains` can't follow, so the device gets **one** first hop toward it: the group's first member, and inspect warns `group ru-entries narrowed to ru-1: nl-1 can't follow`;
- a member without `chains` can't vouch, so it is dropped from a group of two or more (warned);
- `vouch` and `follow` are emitted only toward `chains` nodes.

**Validation** (`netmap.Build` and devmap's checker, with positions):

- **Shape.** A chain's `via` is either one group or single servers; a group followed by anything but the exit is refused: `group ru-entries: in M3 a group may only be the hop before the exit`. The exit is one node (open question 4). A group has 1 to 8 members, each a server, none twice in a chain; a chain has at most `DefaultHopLimit − 2` relays.
- **N9 per member**: every member allows ingress and the exit allows egress (next to `hiddenFromDevices`, `internal/netmap/envelope.go:225`; devmap's in `checker.paths`, `spec.go:872`).
- **Adjacency**: a link between every member and the exit, and between consecutive relays (`PathConfigFrom` would silently drop a non-adjacent first hop).
- **Symmetric routes**: each member and relay routes to the exit and back to each device the chain carries (a next hop equal to the destination delivers). The reverse-path check stays loose in M3.
- **Bound**: the builder computes each chain's failover bound ([formula](#the-bound)) with its `delay_bound`, warns above 12 s and refuses above 15 s.
- **MTU**: refuses an `overlay_mtu` below 576, or below 1280 while the space has IPv6 (see the constraint above).
- **Names**: Build already holds chain names to `CheckChainName` (`rule.go:300`); M3 makes the reader (`rulesWellFormed`, `rule.go:331`) apply it to chain and group names too, as TP-022's review asked.
- **Loops** are refused only by devmap (`plan.go:413`), on paths after expansion; `netmap.Build` has no loop check, and a group adds no relay, so M3 adds none.

**MTU.** A device's TUN MTU today comes from its own links only. A member → exit link with a smaller budget drops larger messages at the member (`ErrPacketTooLong`/`ErrPacketSize`, `link.go:389`) and nothing tells the inner TCP flow: a black hole after a switch. So the builder computes, per node, the minimum budget over every link of every path to its peers, all members included, as `overlay_mtu`; the engine uses the smaller of that and its own. **Every candidate path of a peer carries the same MTU.**

**devmap**:

```yaml
nodes:
  - name: ru-1
    capabilities: [chains]
groups:
  - name: ru-entries
    policy: failover          # failover | lowest-latency | spread
    members: [ru-1, ru-2]     # priority order
chains:
  - name: ru-nl
    via: [ru-entries]         # one group, or single servers in order
    exit: nl-1
```

`via` is optional; without it a chain keeps today's meaning. **One WireGuard device per egress** exists (`routing.go`); M3 proves two chains to two exits at once.

## How a path is proven: vouches, not end-to-end probes

Every grouped path is device → member → exit, and the member already proves its link to the exit every 2 s (TP-006). So instead of the first draft's end-to-end probes, **the member vouches**: the device's link probe names the exit, and the reply says whether the member's link to it is up, how long ago proven, and its unheld round trip.

| | End-to-end probes (first draft) | Vouches (chosen) |
|---|---|---|
| New traffic | a stream per device and member, across the border, timed to the device | none: rides each link's probe; the border carries the server pair's probes only |
| Idle device, two vantages | linked to its exit within the hour | nothing device-timed crosses |
| Proves | the exit's path layer answers through the member | the member ↔ exit link is up both ways |
| Reflection, forged probes | reply limits, tokens, matching | link-local, nothing to reflect |
| Trust, upgrades | member can answer for the exit; exit upgraded | the member's word; members and exit upgraded |
| Single-relay lines | probed past them | first relay's next link only (RR48) |

The trust is the same either way (a member could answer probes itself), and a member that carries traffic can drop it anyway (RR49). What vouches lose is proof past a relay's next link, which M3 doesn't need: lines of single relays have no choice to make. Open question 6 lets the owner reverse this.

**Proof is never WireGuard traffic.** Inbound data doesn't count: its freshness is set before WireGuard authenticates (`bind.go:285`), and it proves only one direction. A vouch reply is a link frame inside the transport's seal: only the adjacent node can forge one, and that node is the member being trusted.

**Up, suspect, down.** A path is:

- **up**: its first-hop link is up and the member's latest vouch says up, received within the link's `DeadAfter`;
- **suspect**: the current path missed one vouch reply; the warm backup is probed at once;
- **down**: the member vouches down, or the device's link to it is down, or a burst probe went unanswered within the probe timeout (a backup is never "up" on old proof);
- **unproven**: linked, no reply yet. `Failover`'s "first linked" fallback takes unproven paths, never down ones.

**Clocks.** A change of cadence (idle → sending, backup → current) restarts both the link's `DeadAfter` clock and the vouch's from the change, with a probe sent at once, so an old warm proof never makes a promoted path dead on arrival.

**Switch at once, and tell the exit.** On detecting the current path down, the device's path layer re-runs the selector from its timer, not on the next `Send`, and asks WireGuard to send one keepalive to the peer: `Device.LookupPeer(key).SendKeepalive()` (pinned wireguard-go, `device/device.go:341`, `device/send.go:81`). It queues an empty data packet, or starts a handshake when no keypair is current (`send.go:345`); the exit adopts the new endpoint only after authenticating either (`receive.go:515`, `:374`) and follows. `SendKeepalivesToPeersWithCurrentKeypair` (`device.go:406`) exists too but sends to every peer; the per-peer call is the right one. So the exit follows even when the device is idle or only downloading.

**Health signals**, each deciding one thing:

| Signal | Decides | Reported as |
|---|---|---|
| First-hop link liveness | the link and every path through it | `neighbor_down`; `no_link_up` when no link is up |
| The member's vouch | which path carries the peer's traffic | `path_down` (warning): the link is up, the member vouches down; `exit_unreachable` (error): every path to an exit in use is down while some link is up (else it is `no_link_up` only) |
| WireGuard's handshake | whether the exit's WireGuard answers | `exit_no_handshake`, only while a path to the exit is up |

- A path is dead by link or vouch, never by the handshake: that failing while vouches pass means the exit's WireGuard is broken.
- **No double counting**: a path with its link down is `neighbor_down` only; while every path is dead, `exit_no_handshake` is withheld for that exit.
- **The 15 s handshake count restarts when the peer's current path changes** (RR48's own proposed fix); TP-212's link-change restart stays for peers without `vouch`.
- **RR48 narrows** to device-to-device peers, peers without `vouch`, and lines of single relays past the first relay's next link.

## Policies

`Selector`s stay pure: the path layer keeps the history and passes it in new `Candidate` and `Choice` fields; `Up` and `RTT` keep today's meaning (the link's). The fields are listed in [the mechanism section](#candidate-and-choice).

- **`failover` (must).** Stay while up, also while suspect; on down take the first up candidate in priority order, else the first unproven one. **Return to primary: yes**, once it has been up for the hold-down: priority is the operator's statement of preference. **Flap damping**: a candidate that went down twice within 5 minutes needs twice the hold-down, doubling to 5 minutes. **A dialed link does not return to its first endpoint** (TP-006's open question): endpoints are alternatives for one hop, and returning costs a fresh disguised handshake.
- **`lowest-latency` (should).** Path RTT = the device's unheld round trip to the member plus the member's vouched unheld round trip to the exit, each a minimum over two minutes. Where `delay_bound` exceeds the control holds, differences below it are noise: it behaves as `failover` and says `latency_unmeasurable`. A lasting difference is required (60 s, max(25 %, 20 ms)), at most one latency switch per 5 minutes. **A member that lies about its leg** could capture the group: the device cross-checks the member's claim against WireGuard's handshake round trip while that member is current (initiation to response, which a member can only lengthen), and twice off by more than max(50 %, 50 ms) disregards its claims for an hour (`latency_disputed`). A member that fast-paths handshakes beats the check: RR68.
- **`spread` (should), on the device only.** Rendezvous hashing, `SipHash(space, device ‖ member)`, highest score among eligible members; eligible = up for the hold-down, or current and up; **if none is eligible, the highest-scored up member** (a restart never ends in `ErrNoPath`). Older nodes read `spread` as `failover`, so their devices sit on the first member (RR71). No relay runs `spread` in M3, so `Choice.Source` is this node.
- **Who leads.** `follow` decides it, not ids: a leading exit can't see the device's side and keeps replying into an entry the device left. Between two devices or two servers `follow` stays unset and the id rule applies.
- **Warmth.** **One warm backup** (next in priority, or next score under `spread`), the rest **cold**: dialed only once the warm one is down. A cold switch adds a disguised handshake (and a dial timeout if blocked), so the bound holds only while the warm backup is up. Cold endpoints stay in the section: route table and kill switch as today.
- **Against steering**, timings are jittered: probe intervals ± 25 % (warm ± 50 %), the hold-down drawn per up-edge from 20–30 s, the suspicion probe sent after a random 0–500 ms. This blurs the timing; it doesn't hide it (RR73).

## The bound

From a break to the first packet on a working path, for a device that is sending, with the warm backup up:

```
T  = 2·MaxControlHold + delay_bound + 2·RTTmax          probe timeout, ≥ 1 s
B1 = D + T/2                                            the device's first hop dies or is blackholed
B2 = Dsrv + P·(1 + j) + T + T/2                         the member ↔ exit link breaks, either direction
```

`D` is the device link's `DeadAfter` (3 × `P`), `Dsrv` the member's server link's (6 s, server links keep TP-006's 2 s cadence because vouches rest on them), `P` = `PathProbe` 2 s, `j` = 0.25, `T/2` the keepalive's trip; the builder assumes `RTTmax` = 500 ms. With `delay_bound` = 0: T = 2 s, **B1 = 7 s, B2 = 11.5 s**; B2 passes 15 s at `delay_bound` ≈ 2.3 s, which the builder refuses. An idle device probes its current path at warm cadence: it notices a break within 3 × `WarmProbe` × 1.5 + T, and an inbound push waits that long (RR69).

**The gate is the switch, not the stream.** The lab gates B (kill to `first_hop_since`) at 15 s. TCP resumes at its next retransmission after the switch (RTO from 200 ms: about 0.2, 0.6, 1.4, 3, 6.2, 12.6, 25.4 s), so the stream's gap is reported, and gated only on no reset or EOF.

## Entry switches keep the exit's session

WireGuard's endpoint for the exit is its node id, so there is no roam and no new handshake; the exit's NAT keys on the device's overlay address and port, which don't change; late packets fall to WireGuard's replay window, lost ones to TCP; every candidate carries `overlay_mtu`; the exit follows on the keepalive.

| Cause | Effect | Answer |
|---|---|---|
| A member's path carries less than the TUN MTU | large segments dropped: a stall | `overlay_mtu`, refused below 576 / 1280 |
| The exit leads (older exit) | replies keep going to the old entry | `follow`; the builder gives such an exit one first hop |
| No backup up | TCP backs off; long gaps end connections at the application | `exit_unreachable` |
| The device's NAT rebinds the backup's mapping | the backup's link dies; its next probe finds out | `WarmProbe` ≤ 15 s on `udp`; TP-084 |
| `DisableSomeRoamingForBrokenMobileSemantics` | it gates `SetEndpointFromPacket` (`peer.go:282`): the exit would stop following (cookie replies go to the packet's endpoint regardless, `send.go:190`) | stays off |
| The exit dies | every connection through it ends | RR70; no exit groups in M3 |

## Status and the local API

- **Peer**: `first_hop_since`, `chains`, `group`, `policy`, and `paths`: per candidate `first_hop`, `state` (`up`, `suspect`, `down`, `link_down`, `unproven`, `cold`), `proven_ago`, `rtt` (zero when not measured), `switches_to`.
- **Egress**: `chain`. **Events**: `entry_switched` (peer, group, from, to, why: `link_down`, `path_down`, `burst_unanswered`, `returned`, `latency`, `spread`), once per edge; the health problems above.
- Relays log next-hop switches until workers report status (TP-022). No entry holds an address.

## Detectability, honestly

- **Device segment**: link probes to the current member and the warm backup, as every link has today; the vouch rides inside, same size class (a 512-byte floor record under `reality`, RR65). Nothing holds or folds them: no adapter implements `ControlWriter` (`transport.go:105`), and `reality` refuses batching, jitter and cover (`reality/transport.go:110`).
- **Border segment**: the server pair's own probes and users' traffic. While a device is idle nothing timed to it crosses, but WireGuard's packets after traffic and the switch keepalive.
- **Both**: a sending device's traffic links it to its exit, as today; an idle one is not linked; the member ↔ exit pairing always shows (RR67).
- **The WireGuard-rhythm module doesn't measure this**: it wants unanswered records at a steady interval (`modules_wgrhythm.go:26-33, 58-63`). M3-10's two-vantage correlation module does; it reports at M3, not gating.

## The lab

**Topology `Chains()`** (`lab/topology.go`): `devices`, `ru`, `nl` and `world` networks, every segment crossing the router where the censor sits; the censor's address sets name `ru` domestic, `nl` and `world` foreign. `lab/maps/chain.yaml`: `ru-entries` = [ru-1, ru-2] with `failover` to nl-1; chain `de` straight to de-1; one rule each.

**Failover** (`lab/failover_test.go`), each a subtest, each gating the switch at 15 s and the stream on no reset or EOF, same exit address and port at the target, gap reported:

1. **Blackhole** the active entry, both families (the gate case). 2. **Process death** of its agent. 3. **Past the first hop**: drop entry ↔ nl-1 both ways, then one way only.
4. **Download**: the device only ACKs. 5. **Idle push**: the device idle 2 minutes, the target pushes after the blackhole; the push arrives within the idle bound plus one retransmission.
6. **Jitter** (netem on ru-1, 60 ± 40 ms, 2 % loss, 5 min): no switch with `failover`, at most one with `lowest-latency`. **Flap** (down 3 s, up 10 s): leaves on the first down, stays away for the damped hold-down.

**Censor modules**: TP-032's `tls-fingerprint` (JA4 allow-list) and `throttle` (foreign flows policed after 16 KiB) in M3-2; the two-vantage `correlation` module in M3-10. Chain rows (`reality chain (ru → nl)`) join the matrix, judged on the device's segment (open question 2).

## Residual risks M3 adds (proposed)

They land in RESIDUAL-RISKS.md with the tickets that create them.

| # | Residual | When | What leaks, to whom | Breaks | Why accepted |
|---|---|---|---|---|---|
| RR66 | The warm backup shows the group | A device whose chain starts with a group | The censor on the device's segment sees two long-lived disguised sessions to hosting addresses, the backup's mostly idle; cold members appear at a switch | C6 | 15 s needs one linked backup; the rest stay cold |
| RR67 | Two vantages link device and exit while it sends | A censor watching both the device's segment and the border | Traffic timing links a sending device to its exit, as without chains; the member ↔ exit pairing shows from its probe stream at all times; nothing device-timed crosses while idle | C6 | A chain hides the exit from the device's segment, not from a censor on both; M3-10 measures it |
| RR68 | An entry's vouch is its word | A malicious or compromised member | It can vouch up while dropping data; claim the lowest latency and capture a `lowest-latency` group (the handshake check catches only a naive liar); keep the exit's follow fresh with WireGuard-shaped junk until the device's authenticated packets move it (`bind.go:285`) | R6 | A member that carries traffic can drop it anyway (RR49); no new crypto (DESIGN rule 4) |
| RR69 | The gap of a switch | Every failover | A sending device loses up to B (7–11.5 s at defaults), TCP resuming at its next retransmission (≤ about 25 s); an idle one notices within the warm bound, so pushes wait that long | R7 | Faster means probing more, which RR66 and RR67 pay for |
| RR70 | An exit's loss | A chain's exit goes down | Every connection through it ends until it is back | R7 | No exit groups in M3 (open question 4) |
| RR71 | Mixed versions | A node without `chains` on a chain | Such an exit narrows its group to one first hop; such a member leaves its group; an older device gets link-only failover, reads `spread` as `failover`, and with the higher id never returns to its primary (both ends follow); a reader ignoring `overlay_mtu` keeps its own MTU | R6, R7 | The builder narrows rather than risk an outage |
| RR72 | No group before a relay | Chains through relays, until relay-follow (M3-L1) | Such a chain has one entry: blocking it ends the chain with no failover | R6 | The alternative replies into dead entries; relay-follow lifts it |
| RR73 | The censor steers failover | A censor that can block addresses briefly | Two short blocks in 5 minutes pin devices to the backup for the damped hold-down, repeatably; blocking all members but one piles `spread` devices onto it; jittered switch and return timings still mark a failover group and its warm backup | C6, R6 | Traffic still flows through an entry the operator listed |

**RR48** narrows as above. **RR49** widens (paranoid 14): an entry also learns, from the vouch probes its devices send, which exits their chains reach.

## Rollout and older nodes

- Ignored fields read as today (`failover`, the id rule, link liveness, own MTU), so `min_reader` stays. Older nodes drop vouch probes as malformed; devices send them only to `chains` members.
- Upgrades aren't atomic; narrowing by `capabilities` keeps a half-upgraded space working (RR71).

## Moves to internal/dataplane/path/doc.go at M3-4

Mechanism, here until M3-4a/b move it; `path/doc.go` isn't edited now.

### Frames

Vouch probes are link frames, like TP-006's probes, and stay on one link:

```
vouch probe:  kind=4 | flags [1] | token [8] | destination [8] | zero [14]                                (32 bytes)
vouch reply:  kind=5 | flags [1] | token [8] | destination [8] | up [1] | proven ago, ms [2] | rtt, ms [2] | zero [9]
flags:        bit 0 unheld (sent with WritePacket; answered the same way)
```

- A reply is to the token; it proves the link like a link probe reply, so on a link where vouch probes run they replace link probes: one stream per link.
- A node answers for a destination it has a route to, on the arrival link only, at most 20 replies a second per link (per source and arrival link, since the asker is the link's neighbor); the rest dropped and counted. `up` is its link liveness to the destination; `rtt` its minimum unheld round trip, zero when unmeasured. Server links send one unheld probe per `WarmProbe` for that.
- 32 bytes both ways, a keepalive's size class. `frame.go`'s comment ("WireGuard message") gains the kinds.

### Rates

| Link | Probes | Default |
|---|---|---|
| Device → current member, sending (a WireGuard packet out within 30 s) | vouch probe | `PathProbe` 2 s ± 25 %, `DeadAfter` 3 × |
| Device → current member, idle; warm backup | vouch probe | `WarmProbe` 20 s ± 50 % (≤ 15 s on `udp`), `DeadAfter` 3 × |
| Device → cold member | none, no link | dialed on demand |
| On suspicion | one vouch probe to the warm backup after 0–500 ms; unanswered within `T` marks it down and dials the next cold member | |
| Server ↔ server | link probes, as TP-006, jittered ± 25 % | 2 s, `DeadAfter` 6 s |

### Candidate and Choice

`Candidate` gains `PathUp`, `PathUpFor`, `Suspect`, `Refuted` (down by evidence: a down vouch or an unanswered burst), `PathRTT` (the two-minute minimum, device leg plus vouched leg), `PathRTTWorst` (the largest sample in 60 s), `Downs5m`, `HoldJitter` (drawn per up-edge). `Choice` gains `Source` (this node), `CurrentSince`, `LastSwitchAgo` and `LastSwitchWhy`. The path layer fills them; `Up`, `UpFor` and `RTT` stay the link's. M3-4b owns the fields; M3-6 only reads them.

### Policy mechanics

- `failover` hold-down: `HoldDown × (1 + HoldJitter)` × 2^(downs in 5 min − 1), at most 5 min. Return needs `PathUpFor` beyond it.
- `lowest-latency`: switch when `cand.PathRTTWorst` is below `current.PathRTT` by max(25 %, 20 ms), the candidate has been up for the hold-down, and not (`LastSwitchWhy` = latency and `LastSwitchAgo` < 5 min). Down paths are left at once.
- `spread`: score = `SipHash(space key, Source ‖ member)`; eligibility as above.
- Switch at once: a state change of the current path (link down, vouch down, burst unanswered) runs the selector under the peer's lock from the timer, sets `current` and calls the Bind's switch hook, which the engine wires to `LookupPeer(key).SendKeepalive()`.

## M3 plan (until the tickets are filed)

### Tickets

Sizes S/M/L as on the board. Files are listed so parallel work doesn't collide with the Windows design (`tp-047-windows-design`), TP-133 (`localapi.proto`, `internal/agent/localapi`, `api-overview.md`) or TP-197 (`internal/agent/status.go`, `node.go`, `internal/dataplane/engine.go`, `routing.go`).

| Id | Title | Size | Depends on | Files |
|---|---|---|---|---|
| M3-1 | Lab: chain topology, impairment, kill helpers | M | — | `lab/topology.go`, `lab/kill.go`, `lab/README.md`; `lab/impair.go` is TP-162's API under 3a |
| M3-2 | Censor: TLS fingerprint allow-list and volume throttle (TP-032) | M | — | new `lab/censor/modules_tlsfingerprint.go`, `modules_throttle.go`; `lab/censor/doc.go`, `lab/results_test.go`, `lab/RESULTS.md`, `docs/design/lab.md` |
| M3-3a | Map: the new proto fields; the reader applies `CheckChainName` | S | — | `proto/thinkpol/netmap/v1/netmap.proto`, `proto/gen/…/netmap`, `internal/netmap/{section,rule}.go` |
| M3-3b | Builder: groups, `via`, `capabilities`, narrowing, shape and N9 checks, symmetric routes, bound check | M | M3-3a | `internal/netmap/envelope.go`, `internal/devmap/{spec,plan,describe}.go`, `reference.yaml`, testdata, `lab/maps/chain.yaml` |
| M3-3c | Builder and engine: `overlay_mtu` | S | M3-3a | new `internal/netmap/mtu.go`, `internal/dataplane/overlay.go`, tests |
| M3-4a | Path: vouch frames, answering, limits | M | — | `path/{frame,node}.go`, new `path/vouch.go`, `path/doc.go` (frames) |
| M3-4b | Path: path state, `Candidate`/`Choice` fields, suspicion, three-state `follow`, switch at once and the hook | M | M3-4a | `path/{bind,select,node}.go`, new `path/pathstate.go`, `path/doc.go` |
| M3-4c | Path: link cadence (active/warm/cold, jitter, clock restart, unheld server samples), own lab check | S | M3-4b | `path/link.go`, `path/node.go` (dialing), `lab/cadence_test.go` |
| M3-5 | Engine: chains end to end, two exits at once, the keepalive hook | M | M3-1, M3-3b, M3-4b, TP-197 | `internal/dataplane/{paths,routing,engine}.go`, new `lab/chain_test.go` |
| M3-6 | Path: the policies, and the policy → `Selector` wiring | M | M3-3a, M3-4b; merges after M3-5 (`paths.go`) | `path/select.go`, `select_test.go`, `failover_test.go`, `internal/dataplane/paths.go`, `path/doc.go` "Hop groups" |
| M3-7 | Status, events, health for paths; the handshake count restarts on a path change | M | M3-4b, M3-5, TP-133, TP-197 | `localapi.proto` + gen, `internal/agent/{status,events}.go`, `internal/agent/localapi`, `cmd/thinkpol/status.go`, `internal/dataplane/engine.go` (`FirstInitiationSinceLinkUp`), `docs/design/api-overview.md`, `RESIDUAL-RISKS.md` |
| M3-8 | Lab: failover (TP-031's acceptance) | M | M3-1, M3-5, M3-6, M3-7, TP-133, TP-197 | new `lab/failover_test.go` |
| M3-9 | M3 acceptance (TP-033) | S | M3-2, M3-8, M3-10, TP-029 | `lab/results_test.go`, `lab/RESULTS.md`, `docs/design/milestones.md` |
| M3-10 | Censor: two-vantage correlation module, reported not gated | M | M3-1; merges after M3-2 | new `lab/censor/modules_correlation.go`, `lab/censor/doc.go`, `lab/results_test.go`, `lab/RESULTS.md`, `docs/design/lab.md` |
| M3-L1 | Later: relay-follow (a relay answers a device through the neighbor its last packet came from), then lifting "group only before the exit", and vouches past a relay | M | M3-4b | `path/node.go`, `path/select.go`, `internal/devmap/spec.go` |

**Acceptance** (beyond the sections above): M3-4b on the fake clock moves traffic within B2 when a member vouches down, and a promotion isn't dead on arrival; M3-4c: idle → sending neither flaps nor redials; M3-5: a middle relay sees only transport ciphertext; M3-6: `spread` balances 1000 devices within 10 % and moves 1/n when a member goes.

**Order.** M3-1, M3-2, M3-3a and M3-4a at once. Then M3-3b, M3-3c, M3-4b and M3-10. Then M3-4c and M3-5; then M3-6 and M3-7; then M3-8 and M3-9. None touches `internal/dataplane/{firewall,routetable,netcfg,dns}`, `internal/agent/service` or the kill switch. TP-030 → M3-3a/b/c, M3-5; TP-031 → M3-4a/b/c, M3-6, M3-7, M3-8; TP-032 → M3-2, M3-10; TP-033 → M3-9.

### Open questions for the owner

Answer as "1a 2b …". None was settled outright by the review decisions; 1 is narrowed, 6 and 7 are new.

1. **How warm is the backup?** (a) One warm backup probed every 10–30 s, a probe on suspicion, the rest cold (recommended by all three reviewers; Fable's "one warm, the rest cold" is now part of it). (b) The warm backup every 2–3 s: the bound holds even for a backup that died since its last probe, at about ten times the idle rhythm. (c) All cold: least to see, each switch adds a disguised handshake, likely past 15 s.
2. **Which segment does "under the lab censor" gate?** (a) The device's segment gates; the border runs the same modules and is reported, with M3-10's correlation (recommended, all three). (b) Both gate.
3. **Netem: take TP-162's impairment API forward?** (a) Yes, M3-1 does its first two boxes (recommended, all three). (b) A minimal helper TP-162 replaces later.
4. **Exit groups.** (a) Not in M3: refused, RR70 (recommended, all three). (b) Allowed with `failover`, connections end on an exit switch.
5. **Device-to-device peers.** (a) Link-only failover as today, no vouches (recommended, all three). (b) Relays vouch for device peers too.
6. **How is a path proven?** (a) Members vouch for their link to the exit in link-probe replies (recommended: no new stream across the border, nothing timed to an idle device; members need `chains`). (b) End-to-end probes, as in the first draft: proof through the exit's path layer, no member upgrade, but a per-device stream across the border.
7. **devmap's default for `capabilities`.** (a) Absent means pre-M3, so groups narrow until each node is marked (recommended: safe while upgrades are partial). (b) Absent means current, as the first draft assumed one version per devmap space.

## Review round 1

Reviews of 34c62d9: go-paranoid (P), Fable 5.2 (F, numbered within its sections), pocket-torvalds (T).

| Finding | Handling |
|---|---|
| P1, F1a.1, T1: a relay behind a group picks its return hop itself | Changed design: groups only before the exit; relay-follow is M3-L1, RR72 |
| P2, F1a.2: no switch without a `Send`; idle or downloading devices strand the exit | Changed design: switch from the timer, `SendKeepalive`; lab cases 4, 5 |
| P3: `follow` unset on the device | Changed design: three states, both ends set |
| P4: old exit plus group | Changed design: `capabilities`, the builder narrows (question 7) |
| P5, P6, F1a.3: a dead backup counts as up; promotion and idle → busy count as failure | Fixed: unanswered burst = down; clocks restart with a probe |
| P7, T3: breaks past the first hop read `neighbor_down` | Fixed: the vouch reply proves the link and reports the path |
| P8: forged probes drain a per-source bucket | Fixed: vouches are link-local, limited per (source, arrival link) |
| P9, T6, F1a.4: bound vs `delay_bound`; switch vs TCP gap | Fixed: formula, builder warns at 12 s and refuses at 15 s, switch gated apart |
| P10, P15: `spread` at relays | Changed design: device only, restart fallback; older nodes in RR71 |
| P11, F1b.1, F1b.2: detectability not measured; nothing holds probes | Fixed: claim removed, facts corrected, M3-10, honest section |
| F1b.3: weigh vouching | Changed design: vouches chosen (table), question 6 |
| F1c.1: censor steering | Jitter, one warm backup, staggered suspicion probe; the rest RR73 |
| F1c.2: a member captures `lowest-latency` | Handshake cross-check; the rest RR68 |
| F1c.3: one-way break | Fixed: link liveness both ways; lab case 3 one-way |
| F2, seven facts | Corrected: return path (removed); `ControlWriter` unused (`transport.go:105`, `reality/transport.go:110`); roaming flag (`peer.go:282`, `send.go:190`); `Followed` follower-only and pre-auth (`bind.go:398`, `:285`), no longer proof; relay drops on `ErrPacketTooLong`/`ErrPacketSize` (`link.go:389`), `ErrMessageSize` is the sender's (`bind.go:323`); loops devmap only (`plan.go:413`); RR58 → RR65 |
| F3, T7: tickets | Fixed: dependencies as asked, M3-3 and M3-4 split in three (cadence alone), M3-L1 and M3-10 added, M3-1 follows Q3 |
| F4: open questions | Reviewers' answers recorded; 6, 7 new |
| T2, T1's label, T5 | `frame.go` comment in M3-4a; `group` adopted; pure selectors, plus `Refuted`, `PathRTTWorst`, `HoldJitter` |
| T8: size and shape | Fixed: mechanism section marked, overlay linked. Rejected: landing RR rows now (decision 14 keeps them proposed) |
| T minor: `Node.Route` under `spread` | Moot |
| P12, P13, P14, P16, P17 | `exit_unreachable` only with a link up, levels set; WireGuard traffic never proof (rest RR68); RR49 widened; MTU caveat and refusals; RR66–RR73 |
