# thinkpol-vpn — Chains and hop groups design

Chains with hop groups and failover (M3: PRD R5–R7, N9, C4's JA3/JA4 and throttling): how a chain gets into the map, how a device finds out a path is broken past its first hop, how it picks between paths, why an entry switch keeps open connections, and how the lab proves it. The entry point is [DESIGN.md](../../DESIGN.md); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

What is already decided stays decided, and this file builds on it: destination routing, hop groups as first hops and next hops, and the ingress and egress settings ([overlay](overlay.md#data-plane-every-node-one-binary)); `chain:<name>` and "chains in use at the same time end at different exits" ([routing](routing.md#routing-rules-and-dns)); traffic shape belongs to the transport ([transports](transports.md)); the path layer's frames, liveness, leader and follower, and `Failover` ([`path`](../../internal/dataplane/path/doc.go), TP-006); control writes and `MaxControlHold` (TP-027); exit health graded by WireGuard's handshake (TP-195, TP-212, RR48).

Why a file of its own: M3 adds a mechanism (end-to-end probes), a decision on every one of TP-031's open policies, and a lab plan. Folded into overlay.md and routing.md it would more than double both, and the probes belong to neither: they are about paths, not destinations or rules. Overlay keeps the model ("hop groups make failover a path-layer decision"); this file holds how. The last section, the M3 plan, goes once its tickets are filed: what stays true moves into this file's other sections and the package docs.

## The model in one paragraph

A chain is a named way out: an exit, reached through one or more hops, each hop a node or a **hop group**. A group is not an object any node sees: at the start of a chain it becomes the device's candidate first hops to the exit (`netmap.Peer.Paths`), in the middle a relay's next hops (`netmap.Route.NextHops`), in both cases in priority order with a **policy** next to them. The device leads: it probes each candidate path end to end, picks one by the policy, and sends WireGuard's packets for the exit through it; the exit follows the path the device's authenticated traffic arrives by. WireGuard's session is with the exit, so a switch of entries changes nothing WireGuard, the exit's NAT or the open connection can see but a short gap and a few reordered packets.

## Chains in the map and the builder

**The map carries no new object for groups.** A device's section already has what it needs: the chain (`Chain{Name, Exit}`), the exit as a peer, and the exit's candidate first hops. A group name, its members' roles and the rest of the chain stay in the spec and the controller (S1, DESIGN rule 5: a node knows only what it needs). New fields, all ignorable by older readers without widening anything (see [Rollout](#rollout-and-older-nodes)):

| Field | Where | Meaning |
|---|---|---|
| `policy` | `Peer` (first hops), `Route` (next hops) | `failover` (0, the default), `lowest_latency`, `spread`. An unknown value reads as `failover` |
| `follow` | `Peer` | This node follows the peer: set by the builder on an exit's (any server's) section for a device peer. Unset: the node-id rule of TP-006 |
| `probe` | `Peer` | Probe the paths to this peer end to end. Set for chain exits in use whose node answers probes |
| `delay_bound` | `Path` | The most the transports along this path may hold a packet, both ways, in milliseconds: the sum of every link's `Shaping.MaxDelay()` at both its ends (the probing ends' control holds come on top, in the probe timeout) |
| `overlay_mtu` | `Section` | The largest TUN MTU every path from this node to its peers carries (below) |

**Validation** (`netmap.Build`, and devmap's checker with positions):

- N9 per member: every member of a chain's first hop allows ingress (`AllowIngress`) and the exit allows egress; middle members need neither (TP-014: a worker's dials to its section's endpoints leave by the uplink whatever its egress). The cross-section check sits next to `hiddenFromDevices` (`internal/netmap/envelope.go`), devmap's next to the ingress check in `checker.paths`.
- **The exit is one node.** A group in the exit position would move WireGuard's session and the exit's NAT, so every connection would break on a switch (R7). The builder refuses it; exit failover is a separate question (open question 4).
- A group has 1 to 8 members (a `Choice` stays small, and the links between two groups grow as their product), each a server, none twice in one chain; a chain has at most `DefaultHopLimit − 2` relays, so the hop limit never ends a valid chain.
- Consecutive hops are adjacent: the builder emits a link between every member of one hop and every member of the next (entries × exit). `PathConfigFrom` drops a first or next hop it isn't adjacent to, so a missing link would silently shrink a group.
- **Routes are symmetric.** Every relay a chain crosses routes to the exit (next hops: the next group's members, or the exit) and back to each device the chain carries (next hops: the previous group's members, or the device itself). This is TP-006's precondition for a strict reverse-path check and, here, for probe replies (they go back the way the probe came). The check stays loose in M3; making it strict is a follow-up once every map is built this way.
- Names: Build already holds chain names to `CheckChainName` (`[a-z0-9-]`, up to 32, `internal/netmap/rule.go`); the reader (`rulesWellFormed`) checks only that a name is set and unique. M3 makes the reader apply `CheckChainName` too, as TP-022's review asked, so a map built by anything else can't put other bytes into the status. Group names use the same rule in the spec and never reach a node. Two chains ending at the same exit are refused already (routing.md).
- Loops: the existing "paths crossing the same relays in opposite directions" refusal covers chains, since a chain is expanded into paths before it.

**One WireGuard device per egress** is built (`exitDevice`, `layout` in `internal/dataplane/routing.go`): each exit a used chain ends at gets a device of its own, allowed the internet. M3 adds nothing there but the proof TP-030 asks for: one rule through `ru-nl` and another straight to a second exit, at the same time, each on its own device. The status names an egress by its chain, not by the device's internal name.

**MTU.** Today each node's TUN MTU is the minimum over its own links' budgets (`path.MessageBudget`) less WireGuard's 32 bytes. A device's links are only the first leg: an entry → exit link with a smaller budget (another transport, other shaping) drops the larger messages (`ErrMessageSize` at the relay), and since the relay can't speak ICMP for an inner TCP flow, the connection stalls on its large segments: a path-MTU black hole that appears only after a switch to that entry. So the builder computes, per node, the minimum budget over every link on every path from it to each of its peers, all group members included, and writes it into the section (`overlay_mtu`); the engine uses the smaller of that and its own links' minimum. Then **every candidate path of a peer carries the same MTU, and a switch never changes it**. An older reader ignores the field and keeps today's per-node value (the mixed-version row, RR68).

**devmap** gets a `groups:` key and a `via:` field on chains, and keeps `paths:` for everything else:

```yaml
groups:
  - name: ru-entries
    policy: failover          # failover | lowest-latency | spread
    members: [ru-1, ru-2]     # priority order: what failover follows
chains:
  - name: ru-nl
    via: [ru-entries]         # hops in order: groups or single servers
    exit: nl-1                # one server with egress: true
```

`via` is new and optional: a chain without it keeps today's meaning (the exit reached by whatever `paths:` lead to it). Every device of the space gets each chain's paths, `[device, member, …, exit]` per member, as it gets the rules today.

## End-to-end probes

Link liveness proves only the first hop. A path is proven end to end by a probe that goes the whole way to the exit and a reply that comes back the same way.

### Format: a message in a packet frame, not a frame kind

The probe travels as an ordinary **packet frame** (kind 1, with destination, source and hop limit) whose message is not WireGuard's:

```
packet frame:  kind=1 | hop limit [1] | destination [8] | source [8] | message
probe:         0x50 | 0 0 0 | token [8] | flags [1] | zero [19]      (32 bytes)
probe reply:   0x51 | 0 0 0 | token [8] | flags [1] | zero [19]      (32 bytes)
flags:         bit 0 unheld (sent with WritePacket; answer the same way)
```

TP-006 left room for "a new frame kind"; a new **message type** inside the packet frame is the better use of it:

- **Relays need no upgrade.** A relay forwards packet frames by destination without reading the message, so probes cross pre-M3 relays as they are. New frame kinds would be dropped by every older relay (unknown kinds are dropped), and every path through one would read as dead.
- **Older destinations drop it.** A pre-M3 exit's path layer hands the message to WireGuard, and wireguard-go drops a message of unknown type. Nothing answers, and the builder doesn't ask (`probe` unset) for a peer whose node can't answer.
- **It never counts as WireGuard's.** `wgType` reads 0 for these types, so a probe or reply refreshes neither `HeardVia` nor following, and WireGuard never sees one: the destination's path layer answers probes before `deliver`, and the prober's takes replies before the Bind's queue.
- **32 bytes is a WireGuard keepalive's size**, so inside the transport a probe falls in the same size class as a keepalive and needs no shaping of its own.

**Answering.** A node answers a probe addressed to itself when its source is one of its peers and it came from an adjacent node of its space: a reply with destination and source swapped, sent **on the link it arrived by** (not by the peer's selector), so the reply retraces the probe's last hop and the relays' symmetric routes take it the rest of the way. Replies are limited per source (20 a second, a token bucket; the rest dropped and counted), so an adjacent node can't use a node as a reflector. The answer is the path layer's alone: no WireGuard key, no new crypto (DESIGN rule 4).

**Matching.** The prober keeps the last 8 outstanding tokens per path (peer, first hop), random as link probes' are. A reply counts once, only if it matches, and only for the first hop it came back through; one that comes back by another hop is counted (`path.probe_reply_other_hop`) and proves nothing.

### What proves a path, and when to probe

A path's proof is either:

- a matching probe reply, or
- WireGuard-authenticated traffic from the peer arriving through that first hop (the `Followed` evidence, which WireGuard adopts only from a packet it authenticated) while this node has been sending through it. Data already flowing both ways is the cheapest proof there is, and probing over it only adds a rhythm.

A reply that comes back through the first-hop link also proves **that link** both ways, so on a link where an end-to-end probe runs, it replaces the link probe: one probe stream per link, never two.

Rates (all `path.Options`, jittered uniformly by the stated fraction; defaults to be tuned in the lab):

| Path | Probes | Numbers |
|---|---|---|
| Active, sending | Only when the last proof is older than `PathProbe` | `PathProbe` 2 s ± 25 % |
| Active, idle (nothing sent for 30 s) | As a warm backup | |
| Warm backup | Background | `WarmProbe` 20 s ± 50 %; at most 15 s for `udp`, whose NAT mappings expire first |
| Every candidate, on suspicion | One burst, at once | when the active path misses its first proof |
| `lowest-latency` | One unheld probe per path per `WarmProbe`, active path included | |

**Suspicion** is what keeps the backups slow and the bound fast: when the active path misses its first proof, every other candidate is probed at once, so by the time the active path is declared dead its backups' state is a second old, not twenty.

**Dead.** An active path without proof for `PathDead` while this node sends through it is dead. `PathDead` = max(7 s, 3 × the probe timeout); the probe timeout = `2 × MaxControlHold` + the path's `delay_bound` + 2 × its smoothed probe round trip, at least 1 s. A first-hop link down (TP-006's `DeadAfter`, 6 s) makes every path through it dead at once. A warm backup is up while its last proof is within 3 × `WarmProbe`.

**Warm links change cadence.** TP-006 probes every link every 2 s; M3 probes a link at `PathProbe` only while it carries a current path that sends, and at `WarmProbe` otherwise, with `DeadAfter` scaled to three intervals of whichever cadence applies. TP-027 asked for exactly this: no probes on links that carried data recently, jittered intervals, warm backups probed less often. Servers' links to each other follow the same rule, so an idle entry → exit link isn't a 2-second metronome on the border segment either.

### Shaping and `MaxControlHold`

Probes and replies leave their **originating end** through `transport.WriteControl`, so a shaping transport may hold each up to `MaxControlHold` (500 ms) to ride with data or a cover unit, or send it as the cover unit; relays forward them as the packets they are, unheld. Hence the timeout above: two holds, plus whatever the path's shaping adds (`delay_bound`), plus the round trip. An unheld probe (`lowest-latency`) goes out with `WritePacket` and is answered the same way; its round trip is a latency sample only on paths whose `delay_bound` is zero beyond the control holds (no batching or jitter anywhere on it). The path layer still never pads.

### What probes reveal, and how they hide

Inside the transport's seal a probe is a 32-byte message: the transport's padding decides what a capture sees (`reality`'s 512-byte floor, RR58; `udp`'s buckets when set). What padding can't hide is **rhythm**, so the design keeps the rhythm thin:

- **On an active path with traffic, no probes at all**: data both ways is the proof. The only probes there are during one-way flows and the seconds after a break.
- **Warm backups and idle paths: one small exchange every 10–30 s per link**, jittered by half, and none where a link probe would have gone anyway: a net cut against today's 2-second link probes on every link.
- **Request and reply are the same size**, like most keepalives in TLS-wrapped protocols; under `reality` both are a floor-sized record.
- **The lab judges it**: the WireGuard-rhythm module runs against the chain rows with probes on, and must pass ([The lab](#the-lab)).

What stays visible, proposed as residual rows: a device holds a warm, mostly idle disguised connection to **every** member of its entry group, which a censor can read as one client with several long-lived sessions to hosting addresses (RR63); and a censor with a vantage on both the device's segment and the entry → exit segment can match a probe on one to the forwarded probe on the other a few milliseconds later, linking an entry to its exit even while no member traffic flows (RR64). User traffic is as correlatable as probes; probes only make the link visible when it would otherwise be quiet.

## Path scoring and the policies

The `Selector` stays the plug-in point (`Peer.Selector` for first hops, `Route.Selector` for next hops). M3 widens what a `Candidate` says and adds one field to `Choice`:

- `Candidate.Up` now means **the path is up**: its first-hop link is up and, for a probed peer, its end-to-end proof is fresh (active: within `PathDead`; backup: within 3 × `WarmProbe`). `UpFor` counts from when both became true. `Suspect` is new: the active path missed a proof. `RTT` is the path's minimum unheld round trip over the last two minutes, zero when it has none; the link's probe RTT stays in `LinkStatus`.
- `Choice.Source`: the packet's source for a relay's next-hop choice, this node for a Bind's. `spread` needs it.

A peer without `probe` gets link liveness only, as today: `Up` is the first-hop link's.

### `failover` (must)

TP-006's `Failover`, with its hysteresis kept and the open policy decided:

- **Stay while up.** The current path stays while it is up, also while suspect.
- **Switch on dead.** When it is dead, take the first candidate in priority order that is up; else the first with a link at all (unproven); else none (`ErrNoPath`).
- **Return to primary: yes, after the hold-down.** An earlier candidate takes over once it has been up for `HoldDown` (20 s), as `TestAFailedOverPairReturnsAfterTheHoldDown` pins: priority order is the operator's statement of which entry they prefer (cheaper, closer, less shared), and staying on a backup forever would ignore it. The follower comes along by following.
- **Flap damping.** A candidate that went down twice within 5 minutes needs twice the hold-down to take over again, doubling per further down in the window, up to 5 minutes. A link that flaps on jitter so never pulls traffic back and forth.
- **A dialed link does not return to its first endpoint** (TP-006's other open question): the endpoints of one node are alternatives for the same hop, and returning would mean a fresh disguised handshake to the same node for no gain. Endpoint priority stays dial-time only.

**Who leads.** TP-006 made the lower node id lead. On a chain that is wrong half the time: the exit can't see the device's side of an entry, so if it leads it keeps sending through an entry the device has left, whose link to the device is dead: replies vanish until the exit's own link to that entry dies, which it may never do. So **the device leads its exits**: the builder sets `follow` on the exit's section for each device peer, and the exit follows the first hop the device's latest authenticated packet came through (it already does so for any follower). Between two devices or two servers the id rule stays.

**The bound.** From a break to traffic on a working path, provided a warm candidate is up:

| Break | Detected by | Time to the switch |
|---|---|---|
| The entry dies or is blackholed | first-hop link (`DeadAfter`), or the path's proof | ≤ about 7.5 s (`PathDead` plus a probe interval's jitter) |
| A link past the first hop breaks (entry → exit) | the path's proof | ≤ about 9.5 s (`PathDead` + `PathProbe` × 1.25) |
| The exit's reply path (exit → entry) | the path's proof, at the device | same as above; then the exit follows on the device's first packet through the new entry |

Both are inside the 15 s TP-031 asks for, with room for TCP: after a 10 s gap its next retransmission (RTO doubling from 200 ms: at about 0.2, 0.6, 1.4, 3, 6.2, 12.6 s) lands on the new path. The bound assumes a backup that is up; if every candidate is down, nothing moves and health says so.

### `lowest-latency` (should)

- **Source: unheld end-to-end probes**, one per path per `WarmProbe`, active path included. Probe RTTs through `WriteControl` are upper bounds and never used (TP-027); neither is WireGuard's handshake round trip, which only the active path ever has. The sample is the minimum over the last two minutes: minimum filters queueing and the occasional hold.
- **Where it can't measure, it says so.** On a path whose `delay_bound` is above the control holds (some link batches or jitters), a difference smaller than that bound is noise; the selector compares only differences beyond it, and if none can be judged it behaves as `failover` and the status says `latency_unmeasurable`.
- **Hysteresis**: a candidate takes over only if its RTT has been below the current path's by at least max(25 %, 20 ms) for 60 s and it has been up for `HoldDown`; at most one latency-driven switch per 5 minutes. A dead path is left at once, as with `failover`.

### `spread` (should)

- **Each device sticks to one member, devices are spread over the members**: rendezvous hashing, `SipHash(space, source ‖ member)`, the highest score among members that are up wins. Members coming or going move only the devices whose top choice they were (1/n of them), and no member needs to know about the others.
- **Hysteresis without per-source state**: a member is eligible only once it has been up for `HoldDown`, or while it is the source's current choice and up. A flapping member loses its devices on the first down and gets them back only after a steady hold-down.
- **No measurement** beyond liveness: `spread` is about volume per entry address, not speed (against volume-based throttling, overlay.md).
- **In the middle of a chain** a relay picks per packet source: `Choice.Source` is the packet's source, and the rule above needs nothing kept per (source, destination), because the hash is stateless and the hysteresis is per member. That is what TP-006 left open ("`Choice` doesn't carry it yet"): one field, no table. `Node.Route` then reports the last next hop used for the destination.

**Middle relays don't probe.** A relay in the middle fails over on its own links only, as today. In `ru-entries → nl-exit` there is no middle; for longer chains, a next hop whose link is up but which can't reach the exit is left only when the device's probes fail through every first hop that depends on it, and the device can't steer the relay. That stays in RR48, narrowed.

## Entry switches keep the exit's session

**Why open connections survive** (R7):

- WireGuard's endpoint for the exit is the exit's node id, never an address; the path layer picks the first hop underneath. WireGuard sees no roam, keeps its keys, counters and timers, and needs no new handshake.
- The exit's NAT (the space's SNAT and the root's masquerade, TP-014) keys on the device's overlay address and port, which don't change: the internet sees the same exit address and port before and after.
- Packets still in flight through the old entry arrive late or not at all; WireGuard's replay window takes the late ones, and TCP retransmits the lost ones.
- The MTU doesn't change: every candidate path carries the section's `overlay_mtu` ([above](#chains-in-the-map-and-the-builder)).
- The exit follows: its replies move to the new entry with the first authenticated packet that arrives through it.
- Every member's endpoints are already the device's links: the route table routes them around the tunnel and the kill switch lets them through, warm or active, as it does every link of the section today. **M3 changes nothing in the kill switch, the firewall, DNS takeover, the route table or the service.**

**What could break it**:

| Cause | Effect | Answer |
|---|---|---|
| A member's path carries less than the TUN's MTU | large segments dropped after the switch: a stalled connection | `overlay_mtu`; the builder refuses a member that would push it under 1280 while the overlay carries IPv6 |
| The exit leads (older exit, or a map without `follow`) | replies keep going to the old entry | `follow`; RR68 for mixed versions |
| A rekey falls in the gap | the initiation is lost, WireGuard retries after 5 s through the new path | nothing to do: within the bound |
| The break lasts longer than the bound (no backup up) | TCP backs off; long gaps end connections at the application | health `exit_unreachable`; nothing a switch can fix |
| The device's own NAT rebinds the backup's mapping | the backup's link dies; its next probe finds out | `WarmProbe` below `udp`'s NAT timeouts; TP-084 for rebinding in general |
| WireGuard's roaming | none: endpoints are ids, and `DisableSomeRoamingForBrokenMobileSemantics` stays off (it would lose cookie replies) | |
| The exit itself dies | every connection through it ends | not a switch of entries; no exit groups in M3 (open question 4) |

## Interplay with exit health

Three signals, each deciding one thing, none counted twice:

| Signal | Decides | Reported as |
|---|---|---|
| First-hop link liveness (TP-006) | the link, and every path through it | `neighbor_down`, `no_link_up` (as today) |
| End-to-end proof (this file) | which path carries the peer's traffic | `path_down` (new): a path to an exit in use is dead while its first-hop link is up; `exit_unreachable` (new): every path to an exit in use is dead |
| WireGuard's handshake (TP-195, TP-212) | nothing about paths: whether the exit's WireGuard answers | `exit_no_handshake`, only while some path to the exit is up |

- **A path is dead** when its first-hop link is down or its end-to-end proof is stale, never because of the handshake. A handshake that fails while probes pass means the exit's WireGuard (its key, its agent) is broken, and another entry wouldn't help.
- **No double counting.** A path whose first-hop link is down is `neighbor_down` only, not also `path_down`. While every path is dead, `exit_no_handshake` is withheld for that exit: the cause is `exit_unreachable`, and the unanswered initiations are its symptom.
- **The 15 s handshake count restarts when the peer's current path changes**, not only when the first hop's active link does: initiations sent through the old path don't count against the new one. That is RR48's own proposed fix ("from when the peer's first hop became the current one"); with probes deciding the path, the link-change restart TP-212 kept stays only for unprobed peers. The flag is no longer raised by links that fail alternately, because the path doesn't change while one of them stays up.
- **RR48 narrows** to what probes don't cover: device-to-device peers, peers without `probe` (older nodes), and a middle relay's next hop that is up but leads nowhere. Its exit-health part stays as written for those.

## Status and the local API

The status already has a peer's `first_hop` and one `Egress` per WireGuard device (`localapi.proto`). M3 adds, all wire-compatible:

- **Peer**: `first_hop_since` (from `Bind.Current`), `chains` (the chains ending at this peer, by name), `policy`, and `paths`: per candidate, `first_hop`, `state` (`up`, `suspect`, `down`, `link_down`, `unprobed`), `proven_ago`, `rtt` (unheld minimum, zero when not measured) and `switches_to` (how often traffic moved to it since the node started).
- **Egress**: `chain`, the chain's name, next to the device.
- **Events**: one typed event per switch (`entry_switched`, with peer, from, to and why: `link_down`, `path_down`, `returned`, `latency`, `spread`), once per edge, never per retry; health's new problems as above.
- **Next hops** (`Node.Route`) are a server's, and a server's per-space status lives in its worker (TP-022's "Later"): until the worker reports status, relays log their next-hop switches and the lab reads the logs. No status entry holds an address.
- **Names**: chain names pass `CheckChainName` at Build and, from M3, at Open; `localapi.Client` keeps sanitizing every string it receives (TP-022), so nothing a map says can act on a terminal even if a reader were wrong.

## The lab

**Topology `Chains()`** (`lab/topology.go`): the `Upstream` lab with servers split by country, every segment crossing the router where the censor sits:

```
 device-a ─┐                    ┌─ ru ─── ru-1, ru-2   (ingress)
 device-b ─┴─ devices ─ router ─┼─ nl ─── nl-1, de-1   (egress)
                                └─ world ─ internet target, camouflage site
```

Networks `devices`, `ru`, `nl` and `world`; documentation names only, addresses picked by Docker. The censor's address sets name `ru` as domestic, `nl` and `world` as foreign. `lab/maps/chain.yaml`: group `ru-entries` = [ru-1, ru-2] with `failover`, chain `ru-nl` via it to nl-1, chain `de` straight to de-1, rules sending one internet prefix through each.

**Killing the active entry**, three ways, each its own subtest:

1. **Blackhole** (the gate case): the router drops everything to and from the active entry's addresses, both families. Silent, like an address the censor just blocked: nothing resets, only liveness can tell.
2. **Process death**: SIGKILL the active entry's agent. Links die with resets; the faster case.
3. **Past the first hop**: the router drops only the active entry ↔ nl-1 segment. The device's links stay up; only end-to-end probes find it.

The **open connection**: the internet target runs a stream echo; device-a sends a numbered 1 KB message every 50 ms through `ru-nl` and reads the echoes. Pass: no reset or EOF, every message echoed in order, the largest gap ≤ 15 s, and the target saw the same source address and port before and after (same exit, same NAT). The same run reads `first_hop` and `first_hop_since` from the local API before and after, and the exit's follow from nl-1's log.

**Jitter, no flapping**: netem on ru-1's interface (delay 60 ms ± 40 ms, 2 % loss, some reordering) for 5 minutes under the stream: zero switches with `failover`, at most one with `lowest-latency`. A second case flaps ru-1 (down 3 s, up 10 s, repeated): traffic leaves it on the first down and stays away for the damped hold-down. netem is TP-162's impairment API; M3 needs only that part (open question 3).

**Censor modules (TP-032)**, each a switchable module of `lab/censor` with its matrix column:

- **`tls-fingerprint` (allow-list)**: computes the client hello's JA3 and JA4 (the clienthello parser exists) and drops TLS connections whose JA4 isn't on its list of common browser fingerprints. Go's default `crypto/tls` client is blocked; the uTLS Chrome hello `reality` sends passes. Non-TLS flows are other modules' business.
- **`throttle` (volume)**: a flow to a foreign address (by the address sets) is policed after N kilobytes, slowed to a rate or frozen (`Throttle` verdict, rate 0), both directions. Domestic flows untouched. Default N = 16 KiB, the figure reported for TLS to foreign hosting, a setting.
- **Server hello** (TP-026's JA3S/JA4S) feeds the matrix's comparison as it does.

The matrix keeps its device-a → server-1 rows (server-1 counts as foreign there, so the throttle bites the direct case) and adds **chain rows**: `reality chain (ru → nl)`, where the device's segment is domestic. Its cells are judged on the device's segment by default; the entry → exit segment is the open question 2. The WireGuard-rhythm column must pass on the chain rows with probes on: that is probes' detectability, measured.

## Residual risks M3 adds (proposed rows)

| # | Residual | When | What leaks, to whom | Breaks | Why accepted |
|---|---|---|---|---|---|
| RR63 | Warm backups show the group | A device whose chain's first hop is a group | The censor on the device's path sees one client holding a mostly idle disguised connection to every member, each carrying one small record pair every 10–30 s | C6 | Failover within 15 s needs a backup that is already linked; cold backups (dial on suspicion) trade the bound for less to see, and are a later setting |
| RR64 | Probes link an entry to its exit | A censor with vantage on both the device's segment and the entry → exit segment | Probe and reply timing on one segment matches the forwarded ones on the other, so the entry's exit is known even while no member traffic flows | C6 | Member traffic is as correlatable; probes only add it in the quiet; jitter and suppression keep them sparse |
| RR65 | A relay can fake a path's liveness | A malicious or compromised entry or relay of the space | It forwards probes and drops data: the device stays on a path that carries nothing, until `exit_no_handshake` (if it also drops handshakes) | R6 | Probes are the path layer's, unauthenticated end to end (no new crypto); a node that drops traffic denies service anyway (RR49) |
| RR66 | The gap of a switch | Every failover | Up to the detection bound (about 7–10 s) of lost traffic; real-time traffic (calls) drops for that long, TCP recovers | R7 | Detecting faster means probing more, which RR63 and RR64 pay for |
| RR67 | An exit's loss | A chain's exit goes down | Every connection through it ends; the chain is down until the exit is back | R7 | No exit groups in M3: another exit is another WireGuard session and NAT (open question 4) |
| RR68 | Mixed versions on a chain | A pre-M3 exit or relay with M3 devices | No `probe` for such an exit: link-only failover (RR48); an exit that ignores `follow` leads when its id is lower and may keep replying through an entry the device left; a reader ignoring `overlay_mtu` keeps its own links' MTU | R6, R7 | Nothing is deployed beyond the owner's nodes; the controller's capability rollout (TP-027's rule) emits these fields only to nodes that report them |

And RR48 narrowed as [above](#interplay-with-exit-health).

## Rollout and older nodes

- Every new map field is one an older reader may ignore without widening anything: a policy reads as `failover`, a missing `follow` as the id rule, a missing `probe` as link liveness, a missing `overlay_mtu` as the node's own links. So `min_reader` stays (TP-027's rule: raise it only for fields older readers must not ignore). What ignoring costs is RR68.
- Probes need nothing of relays and are dropped by older destinations; the builder sets `probe` only for nodes that answer (devmap: every node, since a devmap space runs one version; the controller: by reported capability, M4).

## M3 plan (until the tickets are filed)

### Tickets

Placeholder ids; sizes S/M/L as the board uses them. The first four are lab- or unit-provable and independent of each other. Files are listed so parallel work doesn't collide with the Windows design (branch `tp-047-windows-design`) or with TP-133 (`localapi.proto`, `internal/agent/localapi`, `api-overview.md`) and TP-197 (`internal/agent/status.go`, `node.go`, `internal/dataplane/engine.go`, `routing.go`) still landing.

| Id | Title | Size | Depends on | Files | Acceptance |
|---|---|---|---|---|---|
| M3-1 | Lab: the chain topology, link impairment and kill helpers | M | — | `lab/topology.go`, new `lab/impair.go`, `lab/kill.go`, `lab/README.md` | `Chains()` validates and comes up; netem impairment on one interface seen there only and gone at teardown; blackhole and kill helpers proven on a plain link |
| M3-2 | Censor: TLS fingerprint allow-list and volume throttle (TP-032) | M | — | new `lab/censor/modules_tlsfingerprint.go`, `modules_throttle.go`, `lab/censor/doc.go`, `lab/results_test.go`, `lab/RESULTS.md`, `docs/design/lab.md` | TP-032's three boxes; both columns in the matrix |
| M3-3 | Map: groups, chains `via`, policy, follow, probe, delay bound, overlay MTU, symmetric routes (TP-030's map part) | L | — | `proto/thinkpol/netmap/v1/netmap.proto`, `proto/gen/…/netmap`, `internal/netmap/{section,envelope,rule}.go`, `internal/devmap/{spec,plan,describe}.go`, `reference.yaml`, testdata, new `lab/maps/chain.yaml` | Build refuses an exit group, an ingress-off first-hop member, a member without links to the next hop; routes symmetric for every chain; `overlay_mtu` the minimum over all members' paths; inspect shows it all; goldens; the reader refuses a chain name `CheckChainName` refuses |
| M3-4 | Path: end-to-end probes and path liveness | L | — (fields set directly in tests; M3-3 for the map) | `internal/dataplane/path/{frame,bind,link,node}.go`, new `probe.go`, `path/doc.go` | A break past the first hop is left within the bound on the fake clock; probes cross a relay built without probe support; an old destination drops them; replies rate-limited; no link probe where a path probe ran; warm cadence; leader by `follow` |
| M3-5 | Engine: chains end to end, several exits at once (TP-030's rest) | M | M3-3, M3-1, TP-197 merged | `internal/dataplane/{paths,routing,engine}.go`, new `lab/chain_test.go` | TP-030's boxes: `ru → nl` and straight to `de` at once, each on its own device; a middle relay sees only transport ciphertext (capture); the engine uses `overlay_mtu` |
| M3-6 | Path: the policies (`failover` final, `lowest-latency`, `spread`) | M | M3-4 | `internal/dataplane/path/select.go`, `select_test.go`, `failover_test.go`, `path/doc.go` "Hop groups" | Return after a damped hold-down; no switch under simulated jitter; `lowest-latency` switches once on a lasting difference and never on a held one; `spread` balances 1000 sources within 10 % and moves only 1/n when a member goes |
| M3-7 | Status, events and health for paths | M | M3-4, TP-133 and TP-197 merged | `proto/thinkpol/localapi/v1/localapi.proto` + gen, `internal/agent/{status,events}.go`, `internal/agent/localapi`, `cmd/thinkpol/status.go`, `docs/design/api-overview.md`, `RESIDUAL-RISKS.md` (RR48 and the new rows) | Current entry, since when, chain names, path states in `status -json`; `path_down`, `exit_unreachable` and the withheld `exit_no_handshake` on the fake clock; the handshake count restarts on a path change |
| M3-8 | Lab: failover (TP-031's acceptance) | M | M3-1, M3-5, M3-6 | new `lab/failover_test.go` | The three kills each move traffic within 15 s with the stream intact and the same exit address and port; no flapping under netem jitter; flap damping seen |
| M3-9 | M3 acceptance (TP-033) | S | M3-2, M3-7, M3-8, TP-029 | `lab/results_test.go` (chain rows), `lab/RESULTS.md`, `docs/design/milestones.md` | `ru-entries → nl-exit` under every censor module; the gate kill under the censor; WireGuard-rhythm passes with probes on; matrix regenerated |

**Order.** Start M3-1, M3-2, M3-3 and M3-4 at once: they touch disjoint files (M3-1 and M3-2 meet only in `lab/README.md`, one paragraph each; M3-3 and M3-4 meet only in `internal/dataplane/paths.go`, which M3-4 leaves to M3-5). Then M3-5 and M3-6 in parallel (engine files vs `path/select.go`; M3-6 waits for M3-4's `path/doc.go`). M3-7 after M3-4 and after TP-133 and TP-197 merge. M3-8, then M3-9. None touches `internal/dataplane/{firewall,routetable,netcfg,dns}`, `internal/agent/service` or the kill switch; the Windows design shares only `DESIGN.md`'s index (one line each).

Existing tickets map onto these: TP-030 → M3-3 and M3-5; TP-031 → M3-4, M3-6, M3-7, M3-8; TP-032 → M3-2; TP-033 → M3-9.

### Open questions for the owner

Answer as "1a 2b …". Only what the docs and tickets don't decide.

1. **How warm are backups?** (a) Background probes every 10–30 s, plus a burst on suspicion (recommended: meets 15 s whenever a backup is up; RR63 as written). (b) Every 2–3 s, as links are probed today: the bound holds even for a backup that died since its last probe, at about ten times the idle rhythm per backup. (c) Cold: backups linked only on suspicion: least to see, but each switch adds a disguised handshake (plus a dial timeout for an entry that is blocked), likely past 15 s.
2. **Which segment does M3's "under the lab censor" gate?** (a) The device's segment (device ↔ entries) gates; the entry → exit segment runs the same modules and is reported, not gated (recommended: the chain exists to move the foreign crossing off the member's line; datacenter-to-datacenter crossings are filtered differently, and the lab can't model how). (b) Both segments gate.
3. **Netem for M3: take TP-162's impairment API forward?** (a) Yes: M3-1 does TP-162's first two boxes and TP-162 keeps the added-delay measurement and gate (recommended). (b) No: M3-1 adds a minimal `tc netem` helper of its own, and TP-162 later replaces it.
4. **Exit groups.** (a) Not in M3: the builder refuses a group at the exit, the loss of an exit ends its connections (RR67), recorded as after the MVP (recommended: R7 promises entries only, and an exit switch can never keep a session). (b) Allowed with `failover` in M3, documented as "connections end on an exit switch".
5. **Probing device-to-device peers.** (a) Not in M3: probes run for chain exits in use; device-to-device peers keep link-only failover (RR48) (recommended: a device peer may be offline by design, and probing it shows a rhythm between members' devices). (b) Probe them too while traffic flows.
