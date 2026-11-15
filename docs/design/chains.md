# thinkpol-vpn — Chains and hop groups design

Chains with hop groups and failover (M3: PRD R5–R7, N9, C4's JA3/JA4 and throttling): the map, the builder's refusals, how a device learns a path past its first hop broke, how it picks a path, why an entry switch keeps connections, and the lab. The entry point is [DESIGN.md](../../DESIGN.md); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md), numbered as after TP-217 (so `reality`'s minimal padding is RR65).

It builds on: destination routing, hop groups, ingress/egress ([overlay](overlay.md#data-plane-every-node-one-binary)); `chain:<name>`, chains in use at once end at different exits ([routing](routing.md#routing-rules-and-dns)); shape belongs to the transport ([transports](transports.md)); the path layer ([`path`](../../internal/dataplane/path/doc.go), TP-006); `MaxControlHold` (TP-027); exit health by handshake (TP-195, TP-212, RR48). [Moves to `path/doc.go`](#moves-to-internaldataplanepathdocgo-at-m3-4) is mechanism, here until M3-4 moves it; the plan goes once its tickets are filed.

**Constraint.** M3 changes no kill switch, firewall, DNS takeover, route table or service. One path is touched: `overlay_mtu` lowers the TUN MTU, and below 1280 `IPv6Off` drops the overlay's IPv6 routes (`routetable.go:212`), so the builder refuses it below 576, and below 1280 while the space carries IPv6.

## The model

A chain is a named way out: one exit, reached through hops. In M3 a chain is either **a group straight to its exit** (`[ru-1 | ru-2] → nl-1`: the device's candidate first hops) or **a line of single relays** (`A → B → exit`). A group compiles into a device peer's candidate first hops (`netmap.Peer.Paths`) with a policy; no node sees it as an object. The device leads: it picks a first hop by what each member **vouches** about its link to the exit, and the exit follows the hop the device's last authenticated packet came by. WireGuard's session is with the exit, so an entry switch is only a gap.

**Why a group only directly before the exit.** A relay behind a group picks its hop back toward the device by its own `Failover` (`node.go:528-545`, no following), so it keeps replying into a member the device left. Relay-follow fixes that later (M3-L1, RR72).

## Chains in the map and the builder

**The map carries no group object.** New fields, each one an older reader may ignore without widening anything ([Rollout](#rollout-and-older-nodes)):

| Field | Where | Meaning |
|---|---|---|
| `policy` | `Peer` | `failover` (0, default), `spread`; `lowest_latency` reserved (after M3); unknown reads as `failover`. No `Route` policy in M3: groups are never a relay's next hops |
| `follow` | `Peer` | `unset` (0: TP-006's id rule), `lead`, `follow`. The builder sets `lead` on a device's exit peer and `follow` on the exit's device peer, so a device leads its exits whatever the ids |
| `vouch` | `Peer` | Ask each first hop to vouch for its link to this peer. Set for a chain's exit when the exit and the members are `chains`-capable |
| `group` | `Peer` | The group's name, display only (status, events); checked by `CheckChainName` |
| `delay_bound` | `Path` | The most the transports along device → member → exit may hold a packet, both ways, ms: the sum of each link's `Shaping.MaxDelay()` at both ends |
| `overlay_mtu` | `Section` | The largest TUN MTU every path from this node to its peers carries |

**How the builder knows a node's version.** The map holds none, so devmap's node entry takes `capabilities: [chains]`: the node answers vouch probes, honours `follow`, reads `overlay_mtu`. Absent means pre-M3 (Q7); the controller later fills it from what nodes report (TP-183). With it:

- an exit without `chains` can't follow, so the device gets **one** first hop toward it: the group's first member, and inspect warns `group ru-entries narrowed to ru-1: nl-1 can't follow`;
- a member without `chains` is dropped from a group of two or more (warned); **if no member has `chains`, the group narrows to its first member without `vouch`**, link-only as before M3 (warned);
- `vouch` and `follow` are emitted only toward `chains` nodes. A wrong mark is survived at run time ([unvouched](#how-a-path-is-proven-vouches-not-end-to-end-probes)).

**Validation** (`netmap.Build` and devmap's checker, with positions):

- **Shape.** `via` is one group or single servers; a group before anything but the exit is refused (`group ru-entries: in M3 a group may only be the hop before the exit`). One exit node (Q4). 1 to 8 members, servers, none twice in a chain; at most `DefaultHopLimit − 2` relays.
- **N9 per member**: every member allows ingress and the exit allows egress (next to `hiddenFromDevices`, `internal/netmap/envelope.go:225`; devmap's in `checker.paths`, `spec.go:872`).
- **Adjacency**: member ↔ exit and consecutive relays are linked (`PathConfigFrom` silently drops a non-adjacent first hop).
- **Symmetric routes**: each member and relay routes to the exit and back to each device the chain carries; the reverse-path check stays loose.
- **One way back per relay**: a relay has one next hop toward a device across all its chains. `plan.go:298-300` merges them into a route picked by the relay's own liveness: with `[dev, ru-1, nl-1, de-1]` and `[dev, ru-2, nl-1, fi-1]`, fi-1's replies keep going via ru-1 after dev ↔ ru-1 is blackholed. Refused as the second next hop is added: `relay nl-1 reaches dev-1 back through ru-1 and ru-2; relays can't follow before M3-L1`.
- **Limits**: at most 8 vouched exits per device behind one member (one probe names them); `lowest-latency` refused until M3-L2.
- **Bound** ([formula](#the-bound)) with each chain's `delay_bound`: warned above 12 s, refused above 15 s.
- **Names**: the reader (`rulesWellFormed`, `rule.go:331`) applies `CheckChainName` (`rule.go:300`) to chain and group names too, as TP-022's review asked.
- **Loops**: refused only by devmap (`plan.go:413`); a group adds no relay, so M3 adds no check.

**MTU.** A device's TUN MTU comes from its own links only; a smaller member → exit budget drops larger messages at the member (`ErrPacketTooLong`/`ErrPacketSize`, `link.go:389`) silently: a black hole after a switch. So `overlay_mtu` is, per node, the minimum budget over every link of every path to its peers, members included; the engine takes the smaller of it and its own. **Every candidate path of a peer carries the same MTU.**

**devmap**:

```yaml
nodes:
  - name: ru-1
    capabilities: [chains]
groups:
  - name: ru-entries
    policy: failover          # failover | spread
    members: [ru-1, ru-2]     # priority order
chains:
  - name: ru-nl
    via: [ru-entries]         # one group, or single servers in order
    exit: nl-1
```

`via` is optional; without it a chain keeps today's meaning. **One WireGuard device per egress** exists (`routing.go`); M3 proves two chains to two exits at once.

## How a path is proven: vouches, not end-to-end probes

Every grouped path is device → member → exit, and the member already proves its link to the exit every 2 s (TP-006). So instead of the first draft's end-to-end probes, **the member vouches**: the device's link probe names the exits behind that member (all of them, one probe per tick, so a member shared by two groups keeps one stream), and the reply says, per exit, whether the member's link to it is up and how long ago proven.

| | End-to-end probes (first draft) | Vouches (chosen) |
|---|---|---|
| New traffic | a per-device stream across the border | none: rides each link's probe |
| Idle device, two vantages | linked to its exit within the hour | nothing device-timed crosses until a switch |
| Proves | the exit's path layer answers | the member ↔ exit link is up both ways |
| Forged probes | reply limits, tokens | link-local |
| Trust, upgrades | member can fake the exit; exit upgraded | member's word; members and exit upgraded |
| Single-relay lines | probed past them | first relay's next link only (RR48) |

The trust is the same either way (a member could answer probes itself), and a member that carries traffic can drop it anyway (RR49). What vouches lose is proof past a relay's next link, which M3 doesn't need: lines of single relays have no choice to make. Open question 6 lets the owner reverse this.

**Proof is never WireGuard traffic.** Inbound data doesn't count: its freshness is set before WireGuard authenticates (`bind.go:285`), and it proves only one direction. A vouch reply is a link frame inside the transport's seal: only the adjacent node can forge one, and that node is the member being trusted.

**Up, suspect, down.** A path is:

- **up**: its first-hop link is up and the member's latest vouch says up, received within the link's `DeadAfter`;
- **suspect**: the current path missed one vouch reply; the warm backup gets a burst probe;
- **down**: the member vouches down, or the device's link to it is down, or a **burst probe** went unanswered within the probe timeout `T`. A burst probe is the suspicion probe and the probe sent at a cadence change; a backup is never "up" on old proof;
- **unproven**: linked, no reply yet. `Failover`'s "first linked" fallback takes unproven paths, never down ones;
- **unvouched**: a wrong `chains` mark (a node not running M3 drops kinds 4/5, `frame.go:20`). After a vouch miss, each next probe on the link goes as a pair, vouch and link probe, until a vouch reply returns; link replies keep the link up. Three vouch misses with link replies make the path unvouched: up while its link is (as before M3), `vouch_unanswered`, one vouch probe per `WarmProbe` to notice an upgrade. An M3 member answers every vouch probe, so silence means it doesn't speak them.

**Clocks.** A change of cadence (idle → sending, backup → current) restarts both the link's `DeadAfter` clock and the vouch's, with a burst probe sent at once: an old warm proof never makes a promoted path dead on arrival, and a dead backup promoted on a down vouch is down within `T`.

**Switch at once, and tell the exit.** On detecting the current path down, the path layer re-runs the selector from its timer, not on the next `Send`, and, with every path-layer lock released ([the hook](#the-switch-hook)), calls `Device.LookupPeer(key).SendKeepalive()` (pinned wireguard-go, `device/device.go:341`, `send.go:81`; not `SendKeepalivesToPeersWithCurrentKeypair`, which hits every peer). It queues an empty data packet, or starts a handshake when no keypair is current (`send.go:345`); the exit adopts the new endpoint only after authenticating either (`receive.go:515`, `:374`) and follows, even for an idle or downloading device. A second keepalive goes `T` later, after any packet the old path still held.

**Health signals**, each deciding one thing:

| Signal | Decides | Reported as |
|---|---|---|
| First-hop link liveness | the link and every path through it | `neighbor_down`; `no_link_up` when no link is up |
| The member's vouch | which path carries the traffic | `path_down` (warning): link up, vouch down; `exit_unreachable` (error): every path to an exit in use down while some link is up; `vouch_unanswered` (warning) |
| WireGuard's handshake | whether the exit's WireGuard answers; one switch per episode | `exit_no_handshake`, only while a path to the exit is up |

- A path is dead by link or vouch, never by the handshake: that failing while vouches pass means the exit's WireGuard is broken, or a member answers probes but doesn't forward.
- **One switch on no handshake.** On `exit_no_handshake` with the current path up, the device moves to the next up candidate (why `no_handshake`), at most once per exit per episode (until a handshake completes); the left member counts a down for damping and is barred from return for 30 minutes; if the next fails too, the exit is to blame and the device stays.
- **No double counting**: a path with its link down is `neighbor_down` only; while every path is dead, `exit_no_handshake` is withheld for that exit.
- **The 15 s handshake count restarts when the current path changes** (RR48's fix); TP-212's link-change restart stays for peers without `vouch`.
- **RR48 narrows** to device-to-device peers, peers without `vouch`, and lines of single relays past the first relay's next link.

## Policies

`Selector`s stay pure: the path layer passes history in new [`Candidate` and `Choice` fields](#candidate-and-choice).

- **`failover` (must).** Stay while up, also while suspect; on down take the first up candidate in priority order, else the first unproven one. **Return to primary** once it has been up for the hold-down: priority is the operator's preference. **Flap damping**: two downs within 5 minutes double the hold-down, up to 5 minutes. **A dialed link does not return to its first endpoint** (TP-006's open question): returning costs a fresh disguised handshake.
- **`spread` (should), on the device only.** Rendezvous hashing, `SipHash(space, device ‖ member)`, highest score among eligible members; eligible = up for the hold-down, or current and up; **if none is eligible, the highest-scored up member** (a restart never ends in `ErrNoPath`). Older devices read it as `failover` (RR71).
- **`lowest-latency`: should, after M3 (M3-L2).** The member's leg is its word. The honest cross-check: the minimum of the last 5 handshakes through the member while current (initiation to response, no cookie round trips; about 10 minutes of sending) against device leg + claim; a shortfall above max(25 %, 20 ms), the switch margin, disregards the claims for an hour (`latency_disputed`), its RTT then being that minimum alone, and a member with no window is never better than current. Still unreliable: a backup's claim is unchecked until a lie has made it current, idle devices have no samples, an LTE minimum of 5 keeps queueing near the margin, and fast-pathed handshakes beat it (RR68). R6 makes it a should, so M3 ships `failover` and `spread`, the builder refuses it, the frames reserve its fields, and question 8 can pull it back.
- **Who leads, and following without a clock.** `follow` decides it, not ids. A `follow` peer follows `pe.via`, the hop of the device's last authenticated packet (WireGuard sets the endpoint only after authenticating, `receive.go:515`, `:374`), **with no `FollowFor` limit while the exit's link to that hop is up** (`bind.go:398` drops the clock for `follow`): an idle device whose keepalive got no reply is still followed whenever the exit next sends, where TP-006's 6 s (`node.go:69`) made it keep its current hop (`select.go:77-88`). With that hop down, current while up, else the first up. A device that really moves back sends the hook's keepalive through the new hop, moving `pe.via` with it; a late old-path packet authenticated after it moves it back, and the second keepalive `T` later undoes that. Relays are untouched: no WireGuard peer, `Failover` on own links (`node.go:527`); a line chain's exit has one first hop. Unset peers keep the id rule and `FollowFor`.
- **Warmth.** **One warm backup** (next in priority, or next score under `spread`), the rest **cold**: dialed only once the warm one is down. A cold switch adds a disguised handshake (and a dial timeout if blocked), so the bound holds only while the warm backup is up. Cold endpoints stay in the section. A link in several roles (ru-1 current for nl-1, backup for de-1) runs at its fastest role's cadence.
- **Against steering**, timings are jittered: probe intervals ± 25 % (warm ± 50 %), the hold-down drawn per up-edge from 20–30 s, the suspicion probe sent after a random 0–500 ms. This blurs the timing; it doesn't hide it (RR73).

## The bound

From a break to the first packet on a working path, for a device that is sending, with the warm backup up:

```
R  = clamp(srtt + 4·rttvar, 250 ms, 1 s)               per link, from its probe round trips; the cap until sampled
T  = 2·MaxControlHold + delay_bound + R                 probe timeout
B1 = D + T/2                                            the device's first hop dies or is blackholed
B2 = Dsrv + P·(1 + j) + T + T/2                         the member ↔ exit link breaks, either direction
H  = RekeyTimeout + 1/3 s = 5.33 s                      added when an initiation went out < 5 s before the switch
```

`D` is the device link's `DeadAfter` (3 × `P`), `Dsrv` the member's server link's (6 s, server links keep TP-006's 2 s cadence because vouches rest on them), `P` = `PathProbe` 2 s, `j` = 0.25, `T/2` the keepalive's trip. The builder takes `R` at its cap: with `delay_bound` = 0, T = 2 s, **B1 = 7 s, B2 = 11.5 s**; B2 passes 15 s at `delay_bound` ≈ 2.3 s, which the builder refuses. `R` follows the link because a fixed allowance turns bufferbloat on the shared access link into false timeouts on current and backup at once; above the cap a miss marks a backup down (next cold member dialed) or a promoted path down (one more switch), and the link reports `slow_link`. An idle device notices a break within 3 × `WarmProbe` × 1.5 + T, and an inbound push waits that long (RR69).

**`H` is WireGuard's wait.** With no keypair and an initiation sent into the dying path under 5 s before the switch, the keepalive only re-queues; the next initiation waits up to `RekeyTimeout` plus 1/3 s jitter (`send.go:104`, `:111`): B1 + H = 12.3 s, B2 + H = 16.8 s. No probing shortens it; the builder and the gate leave it out (the switch is on time), lab case 7 reports it.

**The gate is the switch, not the stream.** The lab gates B (kill to `first_hop_since`) at 15 s. TCP resumes at its next retransmission after the switch (RTO from 200 ms: about 0.2, 0.6, 1.4, 3, 6.2, 12.6, 25.4 s), so the stream's gap is reported, and gated only on no reset or EOF.

## Entry switches keep the exit's session

WireGuard's endpoint for the exit is its node id: no roam, no new handshake; the exit's NAT keys on the device's overlay address and port, unchanged; late packets fall to the replay window, lost ones to TCP; the exit follows on the keepalive.

| Cause | Effect | Answer |
|---|---|---|
| A path carries less than the TUN MTU | a stall | `overlay_mtu` |
| The exit leads (older exit) | replies keep going to the old entry | `follow`; the builder gives such an exit one first hop |
| No backup up | long gaps end connections | `exit_unreachable` |
| The device's NAT rebinds the backup's mapping | the backup's link dies; its next probe finds out | `WarmProbe` ≤ 15 s on `udp`; TP-084 |
| `DisableSomeRoamingForBrokenMobileSemantics` | gates `SetEndpointFromPacket` (`peer.go:282`): no following (cookies go to the packet's endpoint anyway, `send.go:190`) | stays off |
| The exit dies | every connection through it ends | RR70; no exit groups in M3 |

## Status and the local API

- **Peer**: `first_hop_since`, `chains`, `group`, `policy`, and `paths`: per candidate `first_hop`, `state` (`up`, `suspect`, `down`, `link_down`, `unproven`, `unvouched`, `barred`, `cold`), `proven_ago`, `rtt` (the link's, zero when not measured), `switches_to`.
- **Egress**: `chain`. **Events**: `entry_switched` (peer, group, from, to, why: `link_down`, `path_down`, `burst_unanswered`, `no_handshake`, `returned`, `spread`), once per edge; the health problems above, and `slow_link`.
- Relays log next-hop switches until workers report status (TP-022).

## Detectability, honestly

- **Device segment**: probes to the current member and the warm backup. Vouch frames are 120 bytes both ways, so neither direction nor the exit count shows; not a link probe's 10 or a relayed keepalive's 50, so without a size floor a chain's probes are told from a plain link's (`reality`'s 512-byte floor hides it, RR65). Nothing holds or folds them: no adapter implements `ControlWriter` (`transport.go:105`), and `reality` refuses batching, jitter and cover (`reality/transport.go:110`).
- **Border segment**: the server pair's own probes and users' traffic. While a device is idle nothing timed to it crosses, but WireGuard's packets after traffic and the switch keepalives.
- **Both**: a sending device's traffic links it to its exit, as today; an idle one is not linked unless the censor forces a switch (RR67); the member ↔ exit pairing always shows.
- **The WireGuard-rhythm module doesn't measure this** (it wants unanswered records at a steady interval, `modules_wgrhythm.go:26-33, 58-63`); M3-10's correlation module does, reported, not gating.

## The lab

**Topology `Chains()`** (`lab/topology.go`): `devices`, `ru`, `nl` and `world` networks, every segment crossing the router where the censor sits; the censor's address sets name `ru` domestic, `nl` and `world` foreign. `lab/maps/chain.yaml`: `ru-entries` = [ru-1, ru-2] with `failover` to nl-1, and `ru-de` = [ru-2, ru-1] with `failover` to de-1, so ru-1 is current for one exit and warm backup for the other; one rule each.

**Failover** (`lab/failover_test.go`), each a subtest, each gating the switch at 15 s and the stream on no reset or EOF, same exit address and port at the target, gap reported:

1. **Blackhole** the active entry, both families (the gate case). 2. **Process death** of its agent. 3. **Past the first hop**: drop entry ↔ nl-1 both ways, then one way only.
4. **Download**: the device only ACKs. 5. **Idle push**: idle 2 minutes (keypair current: the switch sends an empty keepalive nobody answers), dev ↔ ru-1 blackholed, ru-1 ↔ nl-1 fine, the target pushes 7 s after the switch (past the old `FollowFor`); it arrives within the idle bound plus one retransmission.
6. **Jitter** (netem on ru-1, 60 ± 40 ms, 2 % loss, 5 min): no switch. **Flap** (down 3 s, up 10 s): leaves on the first down, stays away for the damped hold-down.
7. **Handshake in flight**: idle 4 minutes (no keypair), ru-1 blackholed, then the device sends: its initiation dies, the switch comes within `T`, the first packet within T + H + T/2.
8. **Shared member**: streams on both chains; blackhole ru-1: nl-1's chain moves to ru-2, de-1's stays; one probe stream per device link names both exits.

Unit tests cover the unvouched fallback, the no-handshake switch and its guards, and the relay refusal.

**Censor modules**: TP-032's `tls-fingerprint` (JA4 allow-list) and `throttle` (foreign flows policed after 16 KiB) in M3-2; the two-vantage `correlation` module in M3-10. Chain rows (`reality chain (ru → nl)`) join the matrix, judged on the device's segment (open question 2).

## Residual risks M3 adds (proposed)

They land in RESIDUAL-RISKS.md with the tickets that create them.

| # | Residual | When | What leaks, to whom | Breaks | Why accepted |
|---|---|---|---|---|---|
| RR66 | The warm backup shows the group | A device whose chain starts with a group | The device's segment shows two long-lived disguised sessions to hosting addresses, one mostly idle; cold members appear at a switch | C6 | 15 s needs one linked backup |
| RR67 | Two vantages link device and exit | A censor on the device's segment and the border | A sending device's timing links it to its exit, as without chains; blackholing an idle device's entry and watching the border for the switch keepalives (two, `T` apart) links an idle one on demand; the member ↔ exit pairing always shows | C6 | A chain hides the exit from one segment, not two; M3-10 measures it |
| RR68 | An entry's vouch is its word | A malicious or compromised member | It can vouch up while dropping data (the no-handshake switch catches only dropped handshakes); once left, release a held device packet, which still authenticates, and pull the exit's replies until the device's next packet | R6 | A carrying member can drop traffic anyway (RR49); no new crypto (DESIGN rule 4) |
| RR69 | The gap of a switch | Every failover | A sending device loses up to B (7–11.5 s), plus H (5.33 s) with an initiation in flight, TCP resuming at its next retransmission (≤ about 25 s); an idle one notices within the warm bound, and pushes wait that long | R7 | Faster means probing more (RR66, RR67); H is WireGuard's |
| RR70 | An exit's loss | A chain's exit goes down | Every connection through it ends until it is back | R7 | No exit groups in M3 (Q4) |
| RR71 | Mixed versions | A node without `chains` on a chain | Its exit narrows the group to one first hop; a member leaves its group; an older device gets link-only failover, reads `spread` as `failover`, and with the higher id never returns to its primary; an older reader keeps its own MTU | R6, R7 | The builder narrows rather than risk an outage |
| RR72 | No group before a relay | Chains through relays, until M3-L1 | One entry and one way back per relay: blocking it ends the chain | R6 | The alternative replies into dead entries |
| RR73 | The censor steers failover | A censor that can block addresses briefly | Two short blocks in 5 minutes pin devices to the backup for the damped hold-down; blocking all members but one piles `spread` devices onto it; a block forces RR67's keepalives; jittered timings still mark a group and its backup | C6, R6 | Traffic still flows through a listed entry |

**RR48** narrows as above. **RR49** widens (paranoid 14): an entry also learns, from the vouch probes its devices send, which exits their chains reach.

## Rollout and older nodes

- Ignored fields read as today (`failover`, the id rule, link liveness, own MTU), so `min_reader` stays. Older nodes drop vouch probes as unknown kinds; devices send them only to `chains` members and survive a wrong mark (unvouched).
- Upgrades aren't atomic; narrowing by `capabilities` keeps a half-upgraded space working (RR71).

## Moves to internal/dataplane/path/doc.go at M3-4

Mechanism, here until M3-4a/b move it; `path/doc.go` isn't edited now.

### Frames

Vouch probes are link frames, like TP-006's probes, and stay on one link:

```
vouch probe:  kind=4 | flags [1] | token [8] | n [1] | destination [8] × n | zero …                                     (120 bytes)
vouch reply:  kind=5 | flags [1] | token [8] | n [1] | (destination [8] | up [1] | proven ago, ms [2] | rtt, ms [2]) × n | zero …  (120 bytes)
flags:        bit 0 unheld (from M3-L2; zero in M3)          n: 1 to 8
```

- A reply proves the link like a link probe reply, so vouch probes replace link probes on their link (paired only after a miss).
- A node answers every well-formed vouch probe on its arrival link, at most 20 replies a second per link, the rest dropped and counted. Per destination, `up` is its link liveness, down without a route; `rtt` zero in M3.
- `frame.go`'s comment ("WireGuard message") gains the kinds.

### Rates

| Link | Probes | Default |
|---|---|---|
| Device → current member, sending (a WireGuard packet out within 30 s) | vouch probe | `PathProbe` 2 s ± 25 %, `DeadAfter` 3 × |
| Device → current member, idle; warm backup | vouch probe | `WarmProbe` 20 s ± 50 % (≤ 15 s on `udp`), `DeadAfter` 3 × |
| Device → cold member | none, no link | dialed on demand |
| On suspicion | one burst probe to the warm backup after 0–500 ms; unanswered within `T`: down, next cold member dialed | |
| Server ↔ server | link probes, as TP-006, jittered ± 25 % | 2 s, `DeadAfter` 6 s |

### Candidate and Choice

`Candidate` gains `PathUp`, `PathUpFor`, `Suspect`, `Refuted` (down by evidence: a down vouch or an unanswered burst), `Unvouched`, `Barred` (left on no handshake, under 30 minutes: taken only when nothing else is up), `Downs5m`, `HoldJitter` (drawn per up-edge). `Choice` gains `Source` (this node), `CurrentSince`, `LastSwitchAgo` and `LastSwitchWhy`. The path layer fills them; `Up`, `UpFor` and `RTT` stay the link's. M3-4b owns the fields; M3-6 only reads them. M3-L2 adds `PathRTT` and its window.

### Policy mechanics

- `failover` hold-down: `HoldDown × (1 + HoldJitter)` × 2^(downs in 5 min − 1), at most 5 min. Return needs `PathUpFor` beyond it.
- `spread`: score = `SipHash(space key, Source ‖ member)`; eligibility as above.
- No handshake: the engine calls `Bind.NoHandshake(peer)` on `exit_no_handshake`; once per episode the path layer bars the current candidate, adds a down and re-runs the selector; a completed handshake ends the episode.
- Following: `route` sets `Followed` for a `follow` peer whenever `pe.via` is one of its hops; `FollowFor` applies to the id rule only.

### The switch hook

- A change of `current` off the `Send` path (link down, vouch down, burst unanswered, no handshake, return, `spread`) is decided and set under the peer's lock from the timer. After unlocking, the peer is posted to the Bind's notifier, one goroutine that calls the hook (`LookupPeer(key).SendKeepalive()`, wired by the engine) with **no path-layer lock held** (`ps.mu`, `b.rmu`, the node's), and the second keepalive `T` later. Posts coalesce per peer; the timer never waits on WireGuard.
- Against `Bind.Send`: without a keypair the keepalive reaches `Bind.Send` synchronously (`send.go:345` → `SendHandshakeInitiation` → `SendBuffers`), whose `route` takes `ps.mu` (`bind.go:395`), now free. `current` is published before the post, so that `Send` and later ones take the new hop (a further change posts again). A switch inside `route` on a `Send` fires no hook: that packet moves the exit.
- No path-layer lock is ever held across a call into WireGuard. The fake clock can't show this deadlock: M3-4b tests a real wireguard-go device without a keypair, under `-race`, with a deadline.

## M3 plan (until the tickets are filed)

### Tickets

Sizes as on the board. Files listed against collisions with the Windows design (`tp-047-windows-design`), TP-133 (`localapi.proto`, `internal/agent/localapi`, `api-overview.md`) and TP-197 (`internal/agent/status.go`, `node.go`, `internal/dataplane/engine.go`, `routing.go`).

| Id | Title | Size | Depends on | Files |
|---|---|---|---|---|
| M3-1 | Lab: chain topology, impairment, kill helpers | M | — | `lab/topology.go`, `lab/kill.go`, `lab/README.md`; `lab/impair.go` is TP-162's API under 3a |
| M3-2 | Censor: TLS fingerprint allow-list, volume throttle (TP-032) | M | — | new `lab/censor/modules_{tlsfingerprint,throttle}.go`; `lab/censor/doc.go`, `lab/results_test.go`, `lab/RESULTS.md`, `docs/design/lab.md` |
| M3-3a | Map: proto fields; reader applies `CheckChainName` | S | — | `proto/thinkpol/netmap/v1/netmap.proto`, `proto/gen/…/netmap`, `internal/netmap/{section,rule}.go` |
| M3-3b | Builder: groups, `via`, `capabilities`, narrowing, every validation above but MTU | M | M3-3a | `internal/netmap/envelope.go`, `internal/devmap/{spec,plan,describe}.go`, `reference.yaml`, testdata, `lab/maps/chain.yaml` |
| M3-3c | Builder and engine: `overlay_mtu` | S | M3-3a | new `internal/netmap/mtu.go`, `internal/dataplane/overlay.go`, tests |
| M3-4a | Path: vouch frames (several exits, padded), answering, limits | M | — | `path/{frame,node}.go`, new `path/vouch.go`, `path/doc.go` (frames) |
| M3-4b | Path: path state, unvouched, new fields, suspicion, clockless `follow`, `NoHandshake`, switch at once, notifier | M | M3-4a | `path/{bind,select,node}.go`, new `path/pathstate.go`, `path/notify.go`, `path/doc.go` |
| M3-4c | Path: link cadence (active/warm/cold, jitter, clock restart, bursts), adaptive `T`, own lab check | S | M3-4b | `path/link.go`, `path/node.go` (dialing), `lab/cadence_test.go` |
| M3-5 | Engine: chains end to end, two exits at once, the keepalive hook | M | M3-1, M3-3b, M3-4b, TP-197 | `internal/dataplane/{paths,routing,engine}.go`, new `lab/chain_test.go` |
| M3-6 | Path: `failover`, `spread`, no-handshake bar, policy → `Selector` wiring | M | M3-3a, M3-4b, M3-4c; merges after M3-5 | `path/select.go`, `select_test.go`, `failover_test.go`, `internal/dataplane/paths.go`, `path/doc.go` "Hop groups" |
| M3-7 | Status, events, health for paths; handshake count restarts on a path change; calls `NoHandshake` | M | M3-4b, M3-5, TP-133, TP-197 | `localapi.proto` + gen, `internal/agent/{status,events}.go`, `internal/agent/localapi`, `cmd/thinkpol/status.go`, `internal/dataplane/engine.go` (`FirstInitiationSinceLinkUp`), `docs/design/api-overview.md`, `RESIDUAL-RISKS.md` |
| M3-8 | Lab: failover (TP-031's acceptance) | M | M3-1, M3-4c, M3-5, M3-6, M3-7, TP-133, TP-197 | new `lab/failover_test.go` |
| M3-9 | M3 acceptance (TP-033) | S | M3-2, M3-8, M3-10, TP-029 | `lab/results_test.go`, `lab/RESULTS.md`, `docs/design/milestones.md` |
| M3-10 | Censor: two-vantage correlation, reported | M | M3-1; merges after M3-2 | new `lab/censor/modules_correlation.go`; M3-2's shared files |
| M3-L1 | Later: relay-follow; then groups anywhere, several ways back, vouches past a relay | M | M3-4b | `path/node.go`, `path/select.go`, `internal/devmap/spec.go` |
| M3-L2 | Later: `lowest-latency`, windowed cross-check | M | M3-4c, M3-6 | `path/{select,vouch,link}.go`, `internal/devmap/spec.go` |

**Acceptance** (beyond the above): M3-4b, fake clock: traffic moves within B2 on a down vouch, no promotion dead on arrival; real device: no hook deadlock. M3-4c: idle → sending neither flaps nor redials. M3-5: a middle relay sees only ciphertext. M3-6: `spread` balances 1000 devices within 10 %, moves 1/n when a member goes.

**Order.** M3-1, M3-2, M3-3a, M3-4a at once; then M3-3b, M3-3c, M3-4b, M3-10; then M3-4c, M3-5; then M3-6, M3-7; then M3-8, M3-9. None touches `internal/dataplane/{firewall,routetable,netcfg,dns}`, `internal/agent/service` or the kill switch. TP-030 → M3-3a/b/c, M3-5; TP-031 → M3-4a/b/c, M3-6, M3-7, M3-8; TP-032 → M3-2, M3-10; TP-033 → M3-9.

### Open questions for the owner

Answer as "1a 2b …". 1 is narrowed; 6 and 7 came with round 1, 8 with round 2.

1. **How warm is the backup?** (a) One warm backup every 10–30 s, a burst probe on suspicion, the rest cold (recommended, all three reviewers). (b) Every 2–3 s: the bound holds for a backup that died since its last probe, at ten times the idle rhythm. (c) All cold: least to see, switches likely past 15 s.
2. **Which segment gates "under the lab censor"?** (a) The device's; the border is reported, with M3-10 (recommended, all three). (b) Both.
3. **Netem: take TP-162's API forward?** (a) Yes, M3-1 does its first two boxes (recommended, all three). (b) A minimal helper.
4. **Exit groups.** (a) Not in M3, RR70 (recommended, all three). (b) `failover` only; connections end on a switch.
5. **Device-to-device peers.** (a) Link-only failover, no vouches (recommended, all three). (b) Relays vouch for them too.
6. **How is a path proven?** (a) Member vouches (recommended: no new border stream, nothing timed to an idle device; members need `chains`). (b) End-to-end probes: no member upgrade, a per-device border stream.
7. **devmap's default for `capabilities`.** (a) Absent means pre-M3: groups narrow until marked (recommended). (b) Absent means current.
8. **`lowest-latency` in M3?** (a) After M3, M3-L2: R6's must met, this should not (recommended: still capturable). (b) In M3 with the windowed check, reported, not gated.

## Review round 1

Reviews of 34c62d9 (go-paranoid P, Fable F, pocket-torvalds T); the full table is in d9e9351. Changed: groups only before the exit (P1, F1a.1, T1), timer switch and keepalive (P2, F1a.2), three-state `follow` (P3), narrowing (P4), `spread` device-only (P10, P15), vouches (F1b.3). Fixed: P5–P9, P11, F1a.3–4, F1b.1–2, F1c.3, F2, F3, T2–T7. Into RRs: F1c.1–2, P12–P17. Rejected: landing RR rows now (T8).

## Review round 2

go-paranoid on d9e9351.

| Finding | Handling |
|---|---|
| B1 exit stops following an idle device | `follow` peers follow `pe.via` with no clock while that hop is up; second keepalive at `T`; relays untouched; lab 5 deterministic; held-packet release in RR68 |
| B2 hook deadlock | Notifier calls it with no path-layer lock; ordering vs `Bind.Send`; real-device test |
| 3 handshake wait | `H` in the formula, outside the gate; lab 7; RR69 |
| 4 one exit per probe | Up to 8 per probe, 120-byte frames; lab map shares ru-1; lab 8 |
| 5 `lowest-latency` | Check made honest (window, no cookies, relative margin, RTT once disputed), still capturable: M3-L2, Q8 |
| 6, 7 | Narrow to first member without `vouch`; unvouched fallback |
| 8 dependencies | M3-6, M3-8 on M3-4c |
| 9, 10 | Cadence-change probe is a burst; `T` from measured RTT, 250 ms–1 s |
| 11 one relay, two ways back | Builder refuses; M3-L1; RR72 |
| Q1 entry doesn't forward | One no-handshake switch per episode, damped, barred 30 min |
| Q6 | RR67, RR73; frame sizes corrected |
