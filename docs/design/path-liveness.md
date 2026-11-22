# thinkpol-vpn — Path liveness design

How a node tells that a link to an adjacent node is alive (TP-080). Draft: waits for review and the owner; the code still does what [`path`](../../internal/dataplane/path/doc.go) "Liveness" says. The entry point is [DESIGN.md](../../DESIGN.md); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

**Today.** Each end probes every link whose last proof is older than 2 s (`Options.ProbeInterval`, `node.go:67`), and only a reply to its own probe counts as proof (`link.go:488`). A link with no proof for 6 s (`DeadAfter`) is closed (`link.go:440`); the watcher looks every 500 ms (`node.go:72`). So a link that dies under traffic closes 3.5 to 6.5 s later, and an idle link shows one fixed exchange every 1 to 2 s, forever: 507-byte records on `reality`, 84-byte datagrams on `udp`, 367 each way in 7.5 idle minutes (TP-223). Owner, 2026-11-16: "if liveness checks piggyback on data it's nearly instant. slower dead-link detection when idle is acceptable."

## The rule

Each end judges its own link, one direction at a time. **Any frame the link delivers proves the far-to-near direction**: the transport authenticated it (the `udp` seal, `reality`'s TLS), so it is as good as a probe reply (RR33 applies to both alike). This means data, probes, replies, late replies and frame kinds this node doesn't know. **The near-to-far direction is proven only by what comes back.** So the clock starts at the first frame sent after the last one received, not at the last proof:

| Name | Value | Meaning and reason |
|---|---|---|
| Suspect | 1 s | Something was sent and nothing has arrived for 1 s since the first such send. A frame's answer (a TCP ACK inside the tunnel, a reply) takes one round trip, and 1 s is well above a normal one. A suspect link sends a standalone probe now, and another every 0.75–1.25 s (1 s ± 25 %) until something arrives. |
| Dead | 4 s after that first unanswered send | Nothing arrived: the link is closed and redialed (backoff unchanged, 250 ms to 5 s). This allows three probes, the first with 3 s to come back: that covers two `MaxControlHold`s (1 s, probe and reply, `transport.go:112`) plus a 2 s round trip. |
| Watcher | every 250 ms | The suspect clock is read four times a second. |
| **Dead under traffic** | **≤ 4.25 s** | Measured from the first packet sent into the dead link. Under steady traffic that packet goes out within milliseconds of the death, so the bound is 4.25 s after the death. Today it is 6.5 s, so the new bound is never slower. |

**While data flows both ways, every send is answered within the suspect window and no standalone probe goes out.** A one-way flow (a relay forwarding a UDP stream, say) has its sender probe about once a second among the data, because answers are the only proof that its frames arrive. A WireGuard keepalive (a 32-byte transport message, which the Bind can tell by its size) doesn't start the suspect clock: WireGuard never answers one, and a probe after each keepalive would put a fixed exchange 1 s after every idle start.

**One-way failures.** If near-to-far breaks while far-to-near still delivers, the far end is the deaf one. It suspects, probes, gets no answer and closes the link within 4.25 s. The near end then hears nothing, and if it is sending it closes 4.25 s after that. So the second end closes within 8.5 s, sooner if it redials first.

The dial timeout stays 6 s, and `FollowFor` stays 6 s. Both are `DeadAfter` today. Neither is about liveness: a `reality` dial is a TCP connection plus a TLS handshake, and following is for leader packets that are 6 s old.

## Idle

A link is **idle** once no data frame has crossed it either way for the first idle draw (2–6 s). Keepalives and probes don't count as data. If an idle link has received nothing for its current interval, counted from the later of its last received frame and its last probe sent, it sends one probe. The reply proves both directions.

- **Schedule:** the nominal interval starts at 4 s, doubles at each idle exchange and stops at 16 s. Each interval is drawn uniformly from 0.5 to 1.5 times its nominal value, which gives 2–6 s, 4–12 s, then 8–24 s for as long as the link stays idle. Draws come from `crypto/rand`, the probe tokens' source, so neither the far end nor a censor can predict them. Any data frame either way resets the schedule to its start.
- **Why 16 s, never above 24 s:** a `udp` link from behind a NAT has to send at least every 25 s, the interval WireGuard recommends for persistent keepalives, or its mapping can expire and pushes to the device get lost. One idle schedule for every transport keeps the code and the lab simple (question 2).
- **One end probes at a time.** A probe arriving at the far end is a frame received there, so it restarts the far end's interval too. Each idle exchange moves both ends one step. An exchange comes every min(draw A, draw B): 8–24 s, 13.3 s on average.
- **Dead idle:** an idle probe is a send, so the suspect rule takes over: probes at about 1 s, dead 4 s after the idle probe. **A dead idle link is found within 28.25 s** (a 24 s draw, 4 s, the watcher's 250 ms).
- **Data on a dead idle link:** the first packet starts the suspect clock, so **the link is found within 4.25 s of the first packet that needs it**, whatever its idle proof said.

## What a censor sees

| State | Records of thinkpol's own | Rhythm left |
|---|---|---|
| Data both ways | none | WireGuard's busy rekey: 3 records against 2 every 2 minutes (RR65 (1), TP-237) |
| Data one way | a probe and its reply about every 1 s ± 25 %, among the data | none apart from the data |
| Link lost under traffic | 3–4 probes about 1 s apart | once, at the loss |
| Idle | one exchange (507 bytes each way on `reality`, 84 on `udp`) every 2–6 s, then 4–12 s, then 8–24 s | no fixed interval: consecutive intervals differ by up to 3×. What stays fixed is the exchange's shape, one record each way of one size, and how long the connection lives |

On `reality` the idle cost falls from 367 records each way to about 34 in 7.5 minutes. What still shows: a long-lived TLS connection that exchanges one equal pair of records every 8–24 s, like a WebSocket ping. `reality`'s 512-byte floor (RR65 (2)) makes those pairs unlike the under-100-byte pings of HTTP/2. `udp`'s probe datagrams keep one fixed size (RR30: `udp` is trivially profiled anyway).

**The matrix's idle case** (TP-223 pulled it) can't prove this as it stands. The `wireguard-rhythm` module already passes today's 1.2 s probes on `reality` held idle (TP-223's measurement). Its keepalive signal needs unanswered records, and the probes are answered. So TP-080 adds a **steady-exchange signal** to the module: one record each way of one size, answered within 2 s, recurring 10 times with consecutive intervals within 1 s of each other (the module's existing steadiness choice). It flags today's probes: TP-223's idle trace becomes its test data. It passes the 8–24 s draws: the chance that nine intervals in a row each fall within 1 s of the one before is under 10⁻⁶. The idle hold runs on the path layer's real timers, 7.5 minutes, whatever the lab's WireGuard timer factor. What the case's control should be is question 1.

**Cover records (TP-237)** don't change this design, and this design doesn't wait for them. A transport that sends cover may fold a probe into a cover record (`WriteControl`, up to 500 ms held, already allowed for above). Cover arriving from the far end proves the far-to-near direction like any frame, so busy-side cover would only make probes rarer.

## The WireGuard side

thinkpol sets no persistent keepalive (`internal/dataplane/wg`), and wireguard-go's timers (`device/constants.go`) leave the following. This design removes none of it:

- **The busy rekey.** While traffic flows, the session rekeys every 2 minutes (REKEY_AFTER_TIME), a 3-against-2 burst. This is RR65 (1)'s accepted tell, TP-237's to hide.
- **The passive keepalive.** 10 s after the last data is received (KEEPALIVE_TIMEOUT), the receiving end sends one 32-byte keepalive. It comes once per idle start, not as a rhythm.
- **Handshake retries.** While the peer can't be reached, initiations go every 5 s plus 0–334 ms (REKEY_TIMEOUT and its jitter) for up to 90 s. That is a near-fixed rhythm, during outages only. After a failover the session goes on over the new link, so it lasts no longer than the switch.
- **WireGuard's own deadline,** a new handshake 15 s after unanswered data (KEEPALIVE_TIMEOUT + REKEY_TIMEOUT), is slower than 4.25 s, so links always fail over first.

## Path switching

`Failover`, the follower rule and the 20 s hold-down stay as they are. They read "up", and **up now means proven once and not yet dead** by the rules above. A link no longer drops at a fixed 6 s from its last proof. Among one neighbor's links, `pick` prefers the up link that received last. A sending node therefore switches its first hop or next hop within 4.25 s of its first packet into a dead link. A backup that was idle may be up on proof up to 24 s old. If it turns out dead after a switch, its own 4.25 s clock finds that, so a double failure costs 8.5 s. `Neighbors` reports a never-linked dial as down after its first failed attempt, or 4.25 s after the dial started.

**Where the chains design (docs/design/chains.md, M3 design branch, not approved) must line up:**

1. **The sending deadline.** Chains keeps 6 s for a sending link (`DeadAfter`), and its switch bounds B1 7 s and B2 11.5 s rest on that. With TP-080 the sending deadline becomes 4 s from the first unanswered send. Chains takes that value and its bounds shrink by 2 s, or it says why it keeps 6.
2. **Vouch probes.** Chains sends vouch probes in place of link probes, every 2 s ± 25 % while the device is sending. TP-080 sends no link probes while data flows both ways. Vouches are path probes and stay chains' own to pace. Sent amid data they leave no idle rhythm. On an idle link they should follow this idle schedule.
3. **The idle and warm cadence.** Chains uses 10–30 s with a 90 s deadline and an idle bound of 92 s (47 s on `udp`). TP-080 uses 8–24 s with a 28.25 s idle bound. One schedule should serve both, so a warm backup is an idle link and chains' idle bound (RR69) becomes 28.25 s.
4. **Server-to-server links.** Chains keeps them at a fixed 2 s ± 25 % because vouches report them. TP-080 backs every idle link off (question 3). A vouch then reports an idle member-to-exit link with proof up to 24 s old. The member's link to the exit carries the device's own data, so it is found dead within 4.25 s once the device sends.
5. **Clock restart.** Chains counts a new deadline from a change of cadence without minting proof. That is TP-080's rule already: the clock starts at the first unanswered send. Chains' immediate burst probe at a promotion can come before the 1 s suspect probe without conflict.

## Tests

- **Unit, fake clock (`path`):** a link with data both ways sends no probe frames. A one-way flow probes at 0.75–1.25 s. A link blackholed under traffic closes within 4.25 s of its first unanswered send. The idle schedule's draws stay within 2–6, 4–12 and 8–24 s, cover their ranges and reset on data. A dead idle link closes within 28.25 s, and data on it closes it within 4.25 s. The far end's probe restarts the near end's interval. A keepalive-sized packet starts no suspect clock. Each test gets a mutation check.
- **Lab:** (1) Capture under two-way traffic. On `udp`, probes are told apart by their fixed 84-byte size: none appears. On `reality`, new per-link probe counters in the status stay at zero. (2) Dead under traffic: the link is blackholed mid-stream with a backup present, and the test reports the time to failover, which must be ≤ 4.25 s. (3) Idle: a 7.5-minute hold where each interval between exchanges lies within its draw's range, then a blackhole that must be found within 28.25 s. (4) The matrix's idle case comes back with the steady-exchange signal: `reality` passes, and the control as question 1 settles.
- **What the lab can't show:** real NAT and carrier mapping timeouts (the 25 s assumption); mobile radio stalls, and TCP's retransmission backoff on real networks against the 4 s deadline; a real censor's classifier; sleep and wake on a Mac (`needs_human: macos`, a device checklist item: a link that dies during sleep is found within 4.25 s of the first packet after wake).

## Questions for the owner

1. **What is the idle case's control?** `udp` can't be caught idle once its probes back off too, and an idle thinkpol tunnel sends no WireGuard rhythm (TP-223). The options: (a) a kernel WireGuard reference row with a 25 s persistent keepalive, held idle and caught by the keepalive signal, while `udp` and `reality` are held idle and expected to pass; the steady-exchange signal is pinned on TP-223's idle trace of today's probes. (b) Keep `udp` as the control by giving it a fixed probe interval, a test-only knob. **Recommended: (a).** It is the ticket's "udp as the control" reworded, with no test-only product setting.
2. **How long may the idle interval get?** (a) 8–24 s, found dead within 28.25 s, NAT mappings kept alive on `udp`. (b) 15–45 s, about 18 records each way in 7.5 minutes instead of 34, found dead within 50 s, with `udp` capped at 24 s by a per-transport rule. **Recommended: (a)**, also because one schedule with chains' warm backup keeps their bounds equal.
3. **Do server-to-server links back off when idle?** (a) Yes, like every link. Chains' vouches then report server links on their real proof age. (b) Keep server links at a fixed 2 s ± 25 %, as chains asks, at the cost of a steady rhythm between servers. **Recommended: (a).** The ticket says every link, and under traffic a server link is held to 4.25 s anyway.
