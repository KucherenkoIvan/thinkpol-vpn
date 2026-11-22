# thinkpol-vpn — Path liveness design

How a node tells that a link to an adjacent node works (TP-080). Draft r2, reviewed; waits for the owner. Until then the code does what [`path`](../../internal/dataplane/path/doc.go) "Liveness" says. `RRn`: rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

**Today** (`link.go:438`, `node.go:67-72`): both ends probe every 2 s and close a link 6 s after its last reply, checked every 500 ms. A break is found 4.0–6.5 s later; an idle link shows a fixed exchange every 1–2 s (TP-223). Owner, 2026-11-16: "if liveness checks piggyback on data it's nearly instant. slower dead-link detection when idle is acceptable."

## Acks in the frames

Each frame carries its sequence number and the highest one received from the far end, inside the transport's seal:

```
packet:       kind=6 | hop limit | destination [8] | source [8] | seq [4] | ack [4] | WireGuard message
probe, reply: kind=2, 3 | flags | token [8] | seq [4] | ack [4]
```

An **answer** is a frame whose ack covers a frame of ours still waiting, or a reply to a probe still waiting. Probe replies and WireGuard keepalives (packets with a 32-byte message, told by length at every relay) expect none. A frame without a newer ack proves nothing about our direction, so a deaf far end that keeps sending (a redialing `udp` dialer) can't keep a link up. Numbers start at random per link; an ack for a frame the link never wrote is ignored.

**Older nodes.** A link's first probe is today's 10-byte probe with flag bit 0 ("reads acks") set; the link moves to the new frames once the far end's own probe sets it (older nodes' replies copy the flags back). Toward an older node a link keeps kinds 1–3 and stays up on probes. The TUN loses 8 bytes of MTU.

## Busy links

| Term | Rule |
|---|---|
| Clock | Runs from the write (the handoff to the transport) of the oldest frame still waiting for an answer, accurate to 10 ms. An answer moves the clock to the next unanswered frame. |
| Suspect | A frame queued ≥ S after the clock's start, or a write still blocked at that point, is unanswered R later. S is drawn per clock from 0.5–1.5 s. |
| Probing | A probe at once and another T/2 later; the second also goes to each sibling. |
| Dead | No answer within T of suspect: the link closes, and a dialed link redials. |

R and T are chains' terms. R = clamp(srtt + 4·rttvar, 250 ms, 1 s) from probe round trips, at the cap until measured. T = 2·`MaxControlHold` (500 ms, `transport.go:112`) + the link's delay bound (both ends' `Shaping.MaxDelay`) + R, which gives 1.25–2 s.

**A link that dies under traffic is found ≤ S + R + T after the break: 2.0–4.5 s, plus 20 ms of timers (today 4.0–6.5 s).** This holds at every end that keeps sending, whichever direction broke. Nothing written after the break is acked, and a late ack moves the clock no further than the break.

- **B1.** Neither replies nor keepalives start a clock.
- **B2.** A burst's lone last frame (a TCP ACK) starts a clock nothing follows: no probe, the link turns idle. A burst after a short pause is answered within R. A one-way UDP stream inside makes its sender probe every S + R (1–3 s, drawn); a TCP download isn't one-way, its ACKs carry acks.
- **B3.** An end that only receives is **hinted**: a frame on another of the neighbor's links, or the peer's packets through another hop, while the current link has heard nothing for R, makes the current link suspect. The far end's sibling probe comes within S + R + T/2, so it finds the break within 5.5 s plus the one-way delay (6.5 s plus that path's delay when the way back runs through another node); unhinted, by the idle rule.
- **Up** means answered once and not closed since. A dial that never yields a link is down at its first failure or at `DialTimeout` (6 s), as today.
- **Pick.** Among one neighbor's links the lower node id leads, sticky while up; the higher id sends on the link its latest answer came by. After a one-sided failover they agree within one frame.

## Idle

Each end probes once no answer has come for I, drawn afresh for each wait: **8–24 s on `reality`, 5–14 s on `udp`** (question 2). Probes carry acks, so one end's probe answers the other end and restarts its wait. That makes one exchange per min(two draws): every 13.3 s on average on `reality`, every 8 s on `udp`. **A dead idle link is found within I_max + T: 26 s on `reality`, 16 s on `udp`.** Data sent into a dead idle link finds the break within the busy bound.

- **NAT.** The dialer sends at most I_max + a round trip + `MaxControlHold` apart, about 15 s on `udp`, which is chains' warm cap. The assumption: idle UDP mappings last ≥ 15 s, and TCP mappings last minutes.
- **One draw, not r1's 2–6/4–12/8–24 s ladder:** its short draws found a death sooner only in idle's first seconds, when nothing needs the link, at six exchanges per burst in a learnable pattern.
- **Still a tell (RR65):** a long-lived connection exchanging one record each way of one size (507 bytes on `reality`, 92 on `udp`), never closer than the range's floor. WireGuard's passive keepalive (10 s after the last data) carries an ack and restarts the far end's wait.

## Double failure, bufferbloat

With its second probe a suspect link probes each **sibling** once: the neighbor's other links and the next up candidate of each peer or route on this hop (a one-way flow's first probe is answered, so none). A backup that died idle is found within T/2 of the current link: **double failure ≤ S + R + T + T/2 = 5.5 s**, against 9 s without.

Acks prove frames arrive, not how fast: a draining queue (saturated uplink, deep TCP buffer) never looks dead. **Accepted:** a `reality` TCP stall of S + R + T (a retransmission timeout, a radio stall) closes and redials the link, as today past 4–6.5 s; R above its cap reports `slow_link`, as in chains.

## What a censor sees

| State | thinkpol's own records | Rhythm left |
|---|---|---|
| Data both ways | none | WireGuard's 2-minute rekey (RR65 (1), TP-237) |
| A burst, then quiet | none | as idle |
| One-way stream inside | a probe and reply every 1–3 s, drawn | one reverse record size (RR65) |
| Break under traffic | 2 probes + 1 per sibling | once |
| Idle | one exchange per 8–24 s (`reality`) or 5–14 s (`udp`) | no fixed interval; the exchange's shape (RR65) |

Idle `reality`: about 34 records each way per 7.5 minutes, down from 367. **The matrix's idle case** (pulled by TP-223) returns with a **steady-exchange signal** in `wireguard-rhythm`: ten exchanges in a row of one equal-size record each way after quiet, answered within 2 s, consecutive intervals within 1 s. Today's probes trip it (TP-223's trace is its test data); the draws, under once in 10⁶ on `reality`, about once in 10⁵ on `udp`. Known false positives, listed in `lab/censor/doc.go`: gRPC keepalive PINGs, WebSocket pings, HTTP polling at a fixed interval under a minute. WireGuard's timers don't change (RR65); its 15 s deadline is slower than the busy bound. Cover records (TP-237) carry acks like any frame.

## Chains (docs/design/chains.md, M3 design branch)

1. **Sending deadline:** D drops from 6 s to S + R + T (≤ 4.5 s), so B1 → 5.5 s and B2 → 10 s (the member's exit link carries the device's data).
2. **"Proof is never WireGuard traffic"** still holds: the proof is the ack the adjacent node writes inside the seal.
3. **Vouches** (2 s ± 25 % in the 30 s sending window) stay chains' rhythm, as path proof; a vouch reply counts as an answer.
4. **Warm cadence:** a warm backup is an idle link, at 8–24 s on `reality` (chains: 10–30 s) and 5–14 s on `udp` (within chains' 15 s cap). RR69's idle bound drops from 92 s to 26 s, and from 47 s to 16 s on `udp`.
5. **Clock restart:** counting from a cadence change without minting proof is this clock's rule; a promotion's burst probe is a sibling probe.

## Code and tests

- **One timer per link**, set to its earliest deadline. The write path re-arms it only when a clock starts, and answers only store atomics. The 250 ms watcher and its tick go.
- **`Options`** drops `ProbeInterval` and `DeadAfter` for `SuspectMin`/`Max` (0.5/1.5 s), `AnswerMin`/`Max` (R's clamp, 250 ms/1 s), `IdleMin`/`Max` (8/24 s), `DatagramIdleMin`/`Max` (5/14 s), `DialTimeout` (6 s), `FollowFor` (6 s, its own default) and `Rand` (crypto/rand). Validation: each pair positive with min ≤ max. `Status` adds per link: suspect, probes sent, probes answered.
- **Unit tests**, fake clock and injected `Rand`: one per rule above, each mutation-checked; idle draws checked for spread on their own long stream, not only range (under half of 30 consecutive pairs within 1 s; about 1 in 6 expected).
- **Lab:** (1) no probes under two-way traffic, by size on `udp` and counters on `reality`; (2) a blackhole each way fails over within 4.5 s; (3) `reality` under netem survives a 1 s blackout and closes on S + R + T + 1 s; (4) 7.5 minutes idle in its own lab stream, then a blackhole found within 26 s; (5) the matrix's idle case. Beyond the lab: real NAT timeouts, radio stalls, a real classifier, Mac sleep (`needs_human: macos`).

## Questions for the owner

1. **What is the idle case's control row?** (a) A lab TLS pinger, one fixed record each way at a fixed interval, flagged while `reality` and `udp` pass. Cost: a lab-only program, and acceptance reworded: item 5 "passes for `reality` and `udp`, with a lab fixed-interval TLS pinger as the control"; item 2's "lab capture" becomes "capture on `udp`, probe counters on `reality`". (b) `udp` stays the control with a fixed idle interval. Cost: a product setting only a test uses. **Recommended: (a).**
2. **How far may idle probing back off?** (a) 8–24 s on `reality`, 5–14 s on `udp`: `reality` makes about 270 exchanges an hour, dead idle within 26 s. (b) 5–14 s everywhere: one setting, 16 s, but about 450 an hour on `reality`. **Recommended: (a)**: TCP mappings last minutes, and chains splits its warm cadence the same way.
3. **Should server-to-server links back off when idle?** (a) Yes: a dead idle server link is found within 16 s (`udp`); a device that starts sending through a member whose exit link died unnoticed loses up to B2, 10 s. (b) No: the engine gives server-to-server links a fixed 1.5–2.5 s idle range, so a dead one is known within 4.5 s. Cost: a fixed rhythm between servers, over `udp`, whose timing RR30 already concedes. Under traffic B2 is 10 s either way. **Recommended: (b) while server links are `udp`, (a) once they move to `reality`.**
