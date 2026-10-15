---
id: TP-090
title: "clock_skew health that can't be forged"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: M
depends_on: [TP-074]
refs: [A4, S2, DESIGN#data-plane-every-node-one-binary]
owner: ""
branch: ""
---

## Goal
A node's health names `clock_skew` when a peer's clock disagrees with its own beyond the five-minute margin the transports rely on, and an attacker who captured or withheld authenticated datagrams can't raise it. The operator then knows to fix a clock instead of chasing a link that never comes up.

## Scope
- A `clock_skew` health problem (devices and servers, including what a server's workers see on their dialed links).
- The evidence it is built on, robust against replay. The `udp` receiver can't tell a peer with a skewed clock from a replay of an old capture by one datagram alone, so the evidence needs one of these:
  - (a) Count a stale datagram from a sender the receiver doesn't know only if its sealed time is later than the receiver filter's creation time. This catches a peer that is ahead at once, and a peer D behind after D of uptime; replays of captures from before a restart or redial never count.
  - (b) Remember each (sender, counter) already counted as stale, bounded, so duplicates don't count again.
  - (c) For this classification, remember evicted sender ids for the whole connection-id window, not only while their datagrams could still be fresh.
  - Or something stronger, e.g. measure the offset on links that do come up (a probe reply carrying the responder's sealed clock, answered to a fresh nonce) and warn before the margin is reached.
- A threshold over a sliding window: keep the last N drop times, and report skew if the Nth most recent is within five minutes. A fixed window anchored at the first drop flaps.
- Race-free folding of cumulative per-link and per-listener counts into the node's (forward-only CAS or a mutex; no uint64 underflow when two goroutines fold at once), and per-feed accounting so a listener that goes away doesn't skew the sum.

## Out of scope
- Clock setup and the runbook (TP-074, TP-038).

## Acceptance
- [ ] a test replays the SAME stale datagram 3 times to a fresh receiver (router, listener and dialed link): no `clock_skew`
- [ ] a test replays captures from before a receiver restart or redial: no `clock_skew`
- [ ] a test with a genuinely skewed peer (ahead and behind) raises `clock_skew`
- [ ] the engine and supervisor tests call the real `Status`/`Serve` code, not copies of it; a dialed link that never delivers a packet still reaches health
- [ ] `go test -race` on the touched packages passes
- [ ] DESIGN.md says what `clock_skew` means and what it can't tell apart

## Notes
- **Origin.** TP-074 rounds 1-2 tried this and were cut in round 3 (the last). The round-2 delta review is this ticket's spec, and its findings are recorded in TP-074's `## Review findings` (B1, S3-S6, the replay.go and engine nits).
- **The hole that sank it (proven on TP-074's round-2 head).** A stale datagram only went through the read-only `wouldReplay`, never `admit`, so nothing recorded it. One captured server→device datagram, replayed 3 times by an attacker spoofing the server's address, counted 3 times and met the health threshold of 3. Senders are unknown after a receiver restart, on every redial (a new dialed link has an empty `senders`), once an evicted id expires, and for withheld datagrams. The attack repeats every five minutes with captures up to about 1-2 h old (the connection-id window).
- **Residual to judge explicitly.** An active attacker who withholds every datagram of a new sender for over five minutes, then releases a few, looks like skew under (a)-(c). They are already denying the link, so mislabelling it may be acceptable, but say so.
- Today the stale drops are visible only as transport counters (`udp` `StaleTimestamp`, and the supervisor's per-space `Stale` sent to the worker's telemetry), not in `thinkpol status`.

## Log
- 2026-10-15 created in backlog (cut from TP-074 round 3)
