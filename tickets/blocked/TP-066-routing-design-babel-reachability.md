---
id: TP-066
title: "Routing design: Babel-style reachability within signed paths"
milestone: M3
area: dataplane/path
repo: thinkpol-vpn
size: M
depends_on: [TP-006]
refs: [R5, R6, R7, DESIGN#data-plane]
owner: ""
branch: ""
---

## Goal
A written design, with no code, for how nodes learn reachability beyond their own links: a small Babel-style distance-vector protocol among neighbours that finds working paths inside the set the signed map allows. The controller states the policy (which paths may exist, who may originate which destination); the nodes make the choice (which allowed path is best right now). TP-030 and TP-031 do not wait on this ticket; the design is for a later revisit.

## Scope
- **Protocol shape.** A distance-vector exchange among neighbours only: reachability, cost, withdrawals, sequence numbers set by the origin, hold timers, and flap damping. Routes are keyed by (destination node, origin), and a route is only usable if it stays inside the paths the signed map allows.
- **Loop-freedom.** Compare Babel's feasibility condition (a route is feasible only if its metric beats the feasibility distance recorded for the same origin and sequence number) with our hop groups (TP-031: ordered candidate first hops and next hops) and leader/follower failover (the higher node id follows, and the leader returns to its primary after the hold-down). Decide which of Babel's rules we take as is, which we replace, and why. The comparison goes in a table in Notes.
- **Withdrawals instead of end-to-end probing.** Say how an explicit withdrawal and hold-timer expiry replace the end-to-end probes planned in TP-031's third acceptance item (a new frame kind), what they still cannot see, and whether the probe item is dropped or kept as a backstop.
- **Per-flow hashing for `spread`.** How a relay or device picks among equal-cost next hops per flow without per-flow state on relays. The path layer sees only opaque WireGuard packets and the relay header, so the hash input must be stated (relay header fields, and whether the WireGuard session identifies a flow). Fill the per-(source, destination) gap TP-031 notes for `spread` in the middle of a chain.
- **What each node learns (need-to-know).** A node learns routes only to destinations its signed section names, through its own neighbours. No link-state flooding and no full-map gossip: list exactly which routing messages cross which links, and what a relay learns about destinations it does not serve.
- **Route-origin validation.** Only the node the admin signed may originate a destination. An advertisement for a destination from any other origin is dropped, and only the origin can raise a sequence number. State how the signed map carries that origin binding.
- **Transport and shaping.** Routing messages ride inside the transports like any other control traffic (`transport.WriteControl`, TP-027), so they are shaped with the rest and carry no extra framing a censor could match. Say what rate they may use and how a flood of them is bounded.
- **Bounded state.** Maximum routes per node, per neighbour and per destination; maximum hold timers; what is evicted first when a limit is hit.
- **Attack analysis.** At least: a compromised node advertising false reachability (shorter metric to a destination, a destination it may not originate, a next hop that is not in the signed map, a withdrawal storm); a compromised relay blackholing traffic it is allowed to carry; replayed old advertisements. For each: the mitigation, or the residual risk we accept.
- **VRF framing.** Add to DESIGN that each space's namespace on a shared node is in effect a VRF: its own routes, its own forwarding table (`netmap.Section.Routes`), no leaking between spaces.

## Out of scope
- Real OSPF, BGP, FRR or bird, and any integration with them.
- Link-state flooding of any kind.
- Implementing the protocol. The design turns into implementation tickets (listed in Notes), built after this one is done.
- Changing the map format beyond the fields the design shows it needs; those changes go in a follow-up ticket with their own review.

## Acceptance
- [ ] DESIGN.md has a section on routing within signed paths (under Architecture, next to "Routing rules and DNS") that covers the protocol messages, the feasibility rule, withdrawals, hold timers and damping, origin validation, per-flow hashing for `spread`, what each node learns, bounded state, and the attack analysis
- [ ] DESIGN.md states the VRF framing (each space's namespace on a shared node is a VRF)
- [ ] the Babel-versus-hop-groups-and-failover comparison is in Notes, and each rule we take or drop has its reason written next to it
- [ ] every decision made here is recorded in Notes as one line with its why
- [ ] every attack in the scope list has a stated mitigation or an accepted residual risk
- [ ] TP-030 and TP-031 notes point at the new DESIGN section when this design exists; TP-031's end-to-end probe item is either replaced by the withdrawal design or kept with a reason
- [ ] follow-up implementation tickets are proposed in Notes, with the frame kinds they add and what each one depends on

## Blocked by
Parked until after the daily-use month (Decisions 2026-10-15).

## Notes
- **Parked (author, 2026-10-15):** not needed for ten servers with signed static paths; revisit after the daily-use month has started.
- Related: TP-006 (path layer and `netmap.Section.Routes`, the forwarding table this design feeds), TP-030 (chains), TP-031 (hop groups, failover, probes), TP-027 (shaping and `transport.WriteControl`), TP-037 (map gossip push, the other way the map reaches nodes; this design must not turn it into link-state flooding), TP-034 and TP-035 (controller and topology policy, the source of the signed allowed paths).
- Starting point: TP-006 already keeps forwarding by destination, and only link liveness is detected in M0–M2. This design adds the reachability that TP-006 leaves to the map.

## Log
- 2026-10-13 created in backlog
- 2026-10-15 decision (author, 2026-10-15): parked until after the daily-use month has started
- 2026-10-15 docs (backlog grooming): Blocked by added; Goal no longer gates TP-030/TP-031; refs anchor fixed
