# thinkpol-vpn — Path liveness design

How a node tells that a link to an adjacent node works (TP-080). Draft r3, waiting for the owner; until then [`path`](../../internal/dataplane/path/doc.go) "Liveness" holds. `RRn`: rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

**What changes for the owner**
1. **Wire:** each frame gains 8 bytes (seq, ack) and the TUN MTU drops by 8. Links to older nodes keep today's frames and today's 2 s / 6 s rule.
2. **Scope bullet 1 reversed:** received traffic proves only that the far end reaches us. Only acks prove that we reach it, because a far end that couldn't hear us kept a dead link up 8.5–30 s in review. Data flowing both ways carries acks, so busy links stay up (device run 3).
3. **Dead under traffic**, either direction: 2.0–4.5 s (today 4.0–6.5 s); on shaped links ≤ max(4.5 s, 3.5 s + D), never slower than today. A receive-only end: that plus a round trip; with no hint at all, 26 s on `reality` and 16 s on `udp`.
4. **Idle:** one exchange per 13.3 s on average (8 s on `udp`). A dead idle link is found within 26 s (16 s), a double failure within 5.5 s.
5. **Questions:** the idle control row, the idle range per transport, and whether server links back off.

**Today** (`link.go:438`): both ends probe every 2 s and close a link 6 s after its last reply; idle links show a fixed exchange every 1–2 s (TP-223).

## Acks in the frames

```
packet:       kind=6 | hop limit | destination [8] | source [8] | seq [4] | ack [4] | WireGuard message
probe, reply: kind=2, 3 | flags | token [8] | seq [4] | ack [4]      flags: bit 0 reads acks, bit 1 closing
```

Seq and ack are per link, inside the seal, start at random, and are 32-bit serial numbers (RFC 1982); an ack ahead of our latest seq, or 2³¹ behind it, is ignored. An **answer** is a frame whose ack is newer than any before or covers our latest frame; a deaf far end's stale ack proves nothing once we have written since. Replies, close notices and WireGuard keepalives (32 bytes, told by length at relays) expect no answer.

**Older nodes.** A link sends today's frames under today's rule, with bit 0 set on **every** probe, until a far-end probe sets bit 0 or a new frame arrives. Replies don't count, because older nodes copy the flags back. A lost probe costs 2 s. **Relays** write their own seq and ack. A packet with no room for the 8 bytes (an older node's full-size one) goes out as kind 1 without them, neither counting nor answering; a link carrying only those falls back to the idle rule (mixed meshes only).

## Busy links

| Term | Rule |
|---|---|
| Clock | P is the latest answer (at first, link creation). Once per answer, a frame written ≥ S after our previous one moves P to its write (a new burst). |
| Suspect | No answer within R of a frame written ≥ S after P. S is drawn per P from 0.5 s to max(0.5 s, 1.5 s − D). |
| Probing | A probe at once and another T/2 later, the second also to each sibling. |
| Dead | No answer within T of suspect. The link closes and sends a close notice (bit 1, obeyed without reply); a dialed link redials. |

Only frames that expect an answer count. The terms are the chains design's: R = clamp(srtt + 4·rttvar, 250 ms, 1 s), taken from probe round trips and at the cap until measured. D is both ends' `Shaping.MaxDelay` summed: 0 on `reality`, up to 4 s on `udp` (`shaping.go:29`). T = 2·`MaxControlHold` (1 s) + D + R, a probe's longest round trip.

**A link that dies under traffic is found within S + R + T of its last answer: 2.0–4.5 s unshaped, ≤ max(4.5 s, 3.5 s + D) shaped, plus 20 ms of timers.** Worst case: last answer at a, an unanswered frame at a + 1.5 s, suspect at a + 2.5 s, dead at a + 4.5 s, at any end that keeps sending, whichever direction broke. The last answer trails the break by at most one far-to-near trip; today's last reply trails it as much plus a hold, then today closes 4.0–6.5 s later. So for D ≤ 3 s the new bound is never slower; past 3 s, today's 6 s deadline closes working links. Cost: links shaped past about 1 s also probe under traffic.

- **B1, B2.** Frames that expect no answer start no clock. A burst's lone last frame (a TCP ACK) has nothing after it, so the link simply goes idle. The next burst gets a fresh clock, so a slow first response draws no probe. Only one fresh clock per answer, so a sparse sender (SYN retries 1 s and 3 s apart) is still found within 6 s. A one-way UDP stream makes its sender probe every 0.75–2.5 s; TCP's own ACKs carry acks.
- **Deep send buffers.** A link turns suspect only after S + R with no answer at all. A saturated uplink's acks arrive late but keep advancing.
- **Receive-only end.** If its sending direction broke, the far end's close notice arrives within the busy bound plus a round trip. **Hint:** a frame on another of the neighbor's links, or the peer's packets via another hop, makes a link silent for R suspect: with the far end's sibling probe, 5.5 s plus the one-way delay. **Unhinted** (incoming direction broke, no sibling, or notice lost): the idle rule, 26 s / 16 s; the sender has failed over already, only a redial is later. Rejected: probing when an incoming stream stops, a tell after every one-way stream.
- **Up:** answered once, not closed since. **Pick:** among one neighbor's links the lower id leads, sticky while up; the higher id sends where its latest answer came from. They agree once the leader's next frame arrives (≤ 2 s of shaping plus the one-way delay).

## Idle and double failure

Each end probes once no answer has come for I, drawn afresh for each wait: **8–24 s on `reality`, 5–14 s on `udp`** (question 2). A probe covers the far end's latest frame and so restarts its wait; the reply restarts ours. Data sent into a dead idle link finds out within the busy bound. That gives one exchange per min(two draws). On `reality` that is every 13.3 s on average, 270 an hour, about 34 records each way per 7.5 minutes (today 367). On `udp`, every 8 s, 450 an hour. **A dead idle link is found within I_max + T: 26 s on `reality`, 16 s on `udp`**, plus D when shaped. On `udp` the dialer sends at most about 15 s apart, chains' warm cap; this assumes NAT mappings last at least 15 s. The rhythm left (RR65) is one equal-size record each way, never closer together than the range's floor.

A suspect link's second probe also goes to each **sibling**: the neighbor's other links and the next up candidate of each peer or route on this hop. **A double failure is found within S + R + 1.5·T = 5.5 s** (9 s without sibling probes). Acks prove arrival, not speed, so a draining queue never looks dead. **Accepted:** a `reality` TCP stall longer than S + R + T redials the link, as today's code does past 4–6.5 s.

## What a censor sees

| State | thinkpol's own records | Rhythm left |
|---|---|---|
| Data both ways | none | WireGuard's 2-minute rekey (RR65, TP-237) |
| One-way stream | a probe and reply every 0.75–2.5 s, drawn | one reverse record size |
| Break under traffic | 2 probes, 1 per sibling, 1 close notice | sibling probes leave together, tying the links |
| Idle | one exchange per 8–24 s (`reality`), 5–14 s (`udp`) | the exchange's shape |

**The matrix's idle case** (pulled by TP-223) returns with a **steady-exchange signal** in `wireguard-rhythm`: ten exchanges after quiet of one equal-size record each way, answered within 2 s, consecutive intervals within 1 s. Today's probes trip it (TP-223's trace); the draws, under once in 10⁶ on `reality`, about once in 10⁵ on `udp`. False positives (`lab/censor/doc.go`): gRPC and WebSocket pings, fixed-interval HTTP polling.

## Chains, code, tests

- **Chains** (M3 design branch): the sending deadline falls from 6 s to the busy bound, so B1 is 5.5 s and B2 is 10 s. T is the same term, with `delay_bound` as D. "Proof is never WireGuard traffic" holds (acks are inside the seal); a vouch reply is an answer. A warm backup is an idle link, so RR69's idle bound drops from 92 s to 26 s (47 s to 16 s on `udp`).
- **Code:** one timer per link, armed once per P, at the first frame written ≥ S after P, for that write + R. `Options` swaps `ProbeInterval` and `DeadAfter` for min/max pairs for S, R and I (per transport), plus `Rand`.
- **Tests:** a fake clock and an injected `Rand`, one mutation-checked unit test per rule (old-node switch, relay fallback, serial wrap and close notice included). On its own long run, idle intervals must spread: fewer than half of 30 consecutive pairs within 1 s of each other (expected: 1 in 6 on `reality`, 3 in 10 on `udp`). Lab: no probes under two-way traffic; a blackhole either way fails over within 4.5 s; `reality` under netem rides out a 1 s blackout; after 7.5 idle minutes a blackhole is found within 26 s; `udp` at D = 2 s keeps up 5 minutes and finds a blackhole within 5.5 s; the matrix's idle case.

## Questions for the owner

1. **What is the idle case's control row?** (a) A lab TLS pinger that sends one fixed record each way at a fixed interval. It is flagged while `reality` and `udp` pass. Cost: a lab-only program, and acceptance reworded: item 5 reads "passes for `reality` and `udp`, with a lab TLS pinger as the control", and item 2 reads "capture on `udp`, probe counters on `reality`". (b) `udp` stays the control, with a fixed idle interval. Cost: a product setting only a test uses. **Recommended: (a).**
2. **How far may idle probing back off?** (a) 8–24 s on `reality` and 5–14 s on `udp`: 270 exchanges an hour on `reality`, dead idle within 26 s. (b) 5–14 s everywhere: one setting and 16 s, but 450 exchanges an hour on `reality`. **Recommended: (a).** TCP mappings last minutes, and chains splits its warm cadence the same way.
3. **Do server-to-server links back off when idle?** B2 is 10 s under traffic either way; what differs is a warm backup member's idle link to the exit. (a) Yes: its death is found within 16 s on `udp` (26 s on `reality`), and a switch onto it inside that window costs a second switch, 15.5 s (B1 + B2) or 20 s (B2 + B2): past chains' 15 s gate, within its proviso "the bound holds only while the warm backup is up". Nothing to build; acceptance stands. (b) No: a fixed 1.5–2.5 s idle exchange finds a dead server link within 4.5 s. Costs: its intervals always fall within 1 s of each other, so every idle server pair trips this doc's own steady-exchange signal and the matrix must exclude them; acceptance 4 narrows to "an idle link with a device"; and `Table` needs a per-neighbor server mark from the engine, since the path layer can't tell a server link. **Recommended: (a)**: one rule for every link, as the ticket asks; the rare double failure recovers by itself.
