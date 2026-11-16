---
id: TP-223
title: "The rhythm check sees WireGuard's timing, on a busy and an idle tunnel"
milestone: M2
area: lab/censor
stream: verification
repo: thinkpol-vpn
size: M
depends_on: []
refs: [RR65]
owner: "agent-tp-223"
branch: "tp-223-rhythm-by-timing"
---

## Goal
M2's gate promises `reality` shows no WireGuard rhythm: no 2-minute rekey pair and no fixed-size keepalive records (docs/design/milestones.md, M2 row). Today the lab's rhythm signal only looks at records of 92–404 bytes (lab/censor/doc.go:169-170), so `reality`'s 512-byte floor passes it on size alone, and the matrix's hold pings every 2 s (lab/reality_matrix_test.go:86-87), so an idle tunnel is never tested. Make the check honest, then measure.

## Scope
- The rhythm detector flags WireGuard's rekey pair by timing, at any record size. Its thresholds come from WireGuard's own timers (REKEY_AFTER_TIME, KEEPALIVE_TIMEOUT, persistent keepalive), cited in lab/censor/doc.go, not tuned to any transport's result.
- An idle-tunnel case: the tunnel carries no application traffic for several rekey intervals.
- The reality × active-prober cell: today it accepts any text containing "to the reference during" (lab/results_test.go:547), and its comment admits an IPv6 link can report 0 of n (lab/results_test.go:541-543).

## Out of scope
- Changing any transport's shaping or timing (product code). If `reality` fails the honest check, this ticket stops at the measurement; the fix needs a design note the owner approves first (it would revisit RR65).

## Acceptance
- [x] The detector flags the rekey pair by timing at any record size when the pair stands out: it follows a quiet gap (REKEY_TIMEOUT, 5 s, with no record either way) or brings sizes new to the rekey period. Among steady records of its own size it is blind (lab/censor/doc.go). Thresholds cited from WireGuard's timers in lab/censor/doc.go, the module's own choices (2 s answer window, 1 s steadiness, three occurrences) named as choices.
- [x] Control: plain WireGuard (`udp`) is caught on a busy tunnel.
- [ ] Control: `udp` is caught on an idle tunnel. Not while thinkpol sets no persistent keepalive: an idle thinkpol tunnel sends no WireGuard rhythm (Notes). Waits on the owner's ruling on the idle keepalive promise.
- [ ] An idle-tunnel case exercises the keepalive claim. Built and measured (`rhythmCase(..., true)`, holdTunnel's idle branch; Notes), but out of the matrix until the owner rules, so `make lab-test` stays green.
- [x] `reality`'s result on both cases measured at this branch's head and recorded in Notes, pass or fail; its busy pass is the detector's blind spot, and the cell says so (R1.1, R1.2).
- [x] The reality × prober cell fails unless its verdict judges the tell: a dial to the camouflage target during every probe (count equals probes), or the tell reported unattributable when server-1 dialed the target between probes too (R1.4); IPv6's 0 of n is fixed (`hosts`).
- [ ] Each new or changed check mutation-checked; `make lint`, `make test`, `make lab-test` pass.

## Notes
- From the M2 gate review (2026-11-16).
- Owner decision 2026-11-16: widen the detector (rather than reword the promise).
- RR65 is updated after the measurement (TP-225).
- Measurement at 02284b57 (lab-gotest of the udp and reality rows' off and rhythm cells; each held 7.5 min; the module's trace summed up in the test log):
  - udp, in use (a ping every 2 s): caught at 240.5 s, "WireGuard rekey: records of 240 and 184 bytes exchanged 3 times, the last 2m0s apart" (handshake datagrams stood out at 0 s, 120.3 s and 240.5 s).
  - udp, idle (one ping, then nothing): NOT caught. The trace shows the handshake and ping at 0-1.4 s, then only 84-byte datagrams, 367 each way (thinkpol's path probes, answered, about every 1.2 s), until the probe at 450 s. WireGuard sent nothing while the tunnel was idle: thinkpol sets no persistent keepalive (internal/dataplane/wg), so an idle thinkpol tunnel has no WireGuard keepalives to show, and it rekeys only for traffic. The control can't be caught on an idle tunnel by a WireGuard-rhythm check, so the idle case's reality result says nothing about WireGuard; the matrix keeps expecting udp to fail there (the run fails on that cell) until the owner decides what the idle keepalive claim means.
  - reality, in use: pass, not flagged. The held connection carried 599 and 602 application-data records, every one 507 bytes (the 512-byte floor), both ways about once a second: no size is ever new and nothing follows 5 s quiet, so neither signal can fire. This is the detector's documented blind spot (a pair among records of its size exchanged steadily), reached through the floor and the 2 s path probes, not through timing: a censor that models the steady probes and looks for the extra exchange every 2 minutes isn't what this module is.
  - reality, idle: pass, not flagged; 374 and 375 records, all 507 bytes (the path probes alone).
  - Seen on the side: during both reality holds, about 92 short TLS connections from device-a to server-1:443 over IPv4, one every ~5 s (a handshake, 6 and 2 records, then closed), while the link rode IPv6. Not investigated here.
- Full `make lab-test` at c3d655b0 (the branch's head with origin/rewrite merged): fails on two tests. (1) `udp` against "wireguard-rhythm (idle)": pass, want fail: the control isn't caught on an idle tunnel, as measured above. (2) internal/dataplane/dns `TestResolvConfProblemReportsAWriteThatDoesNotSettle` in the node phase: TP-220's flaky settle test under load (not touched here; it failed the same way in an earlier, aborted full run). Every other matrix cell passed, among them reality against both rhythm cases and against the active prober, and udp against the busy rhythm case.
- Prober cell at 9f1d936b: reality's link rode IPv6 and the verdict read "upstream tell: a connection from [server-1's IPv6] or another address of its host to the reference during every probe (7 of 7), reported, not flagged"; the cell now needs "upstream tell: a connection" (the tell on every probe, at least two) in every flag, either family.
- Open boxes, waiting on the owner: "Control ... caught ... on an idle one" can't hold while thinkpol sets no persistent keepalive (an idle thinkpol tunnel sends no WireGuard records), and `make lab-test` fails on that cell for the same reason. Options for the owner: reword the M2 promise's keepalive part (an idle thinkpol tunnel sends one passive keepalive and then nothing of WireGuard's; the path probes are thinkpol's own 2 s rhythm), or define "idle" as a tunnel whose WireGuard keepalives fire (sparse traffic, or a persistent keepalive), which changes what the idle case holds. Until then the idle case is out of the matrix (R1.7). reality's busy pass is the detector's blind spot: a record count each way shows its rekeys (R1.1).
- **R1.1 (review round 1): reality's busy pass is a blind spot of the detector, not hidden timing.** Counting records each way catches reality's rekeys. Measured offline on whole traces of a lab-gotest at c7c43441 (the udp and reality rows' rhythm cells, both cases, held 7.5 min; `THINKPOL_LAB_TRACES`), times in seconds from the trace's first record, d = records device→server minus server→device on the held connection, sampled where no record came within 0.3 s:
  - (a) imbalance, reality in use: d steps by +1 at 124.5, 246.0 and 366.1 (gaps 121.5 and 120.1, inside 120–210) and is flat in between (each level held about 120 s; 604 and 607 records, all 507 bytes after the TLS handshake's few). Caught. Each step is one rekey tick: the device sends 3 records (ping, initiation, confirming keepalive) and server-1 2 (reply, response) within 6 ms.
  - (a) udp in use (control): +1 at 120.9 on the held flow, which the current detector dropped at 240.9 (the trace ends there); the redialed flow steps at 252.4 and 374.4 (122.0 apart). Same mechanism, sizes 220+240+124 against 220+184.
  - (a) idle, both rows: one +1 step each, the device's single passive keepalive (udp 10.9, reality 15.5), then flat for 7 minutes: no chain, not caught.
  - (b) per tick, as worded (one extra record each way, (2,2) within 10 ms): misses the rekey ticks, which are (3,2), and fires on chance: reality in use has 8 ticks of (2,2) (a ping and a path probe within 10 ms), at 3.5, 27.5, 37.6, 132.0, 142.0, 172.1, 182.1 and 385.0, which make 3 chains 120–210 s apart (3.5/27.5/37.6, 182.1, 385.0), none of them a rekey. Read as "an extra record each way, two from the initiator" ((3,2)), it catches reality's rekeys exactly: ticks at 124.0, 244.3 and 364.9 (gaps 120.3, 120.6), and nothing else; udp's at 120.4 and 240.9 (then 373.3 on the redialed flow). Idle: no such tick on either row.
  - No product code changed and no rule added to the detector (owner decides next). The reality rhythm cell's detail names the blind spot and this result (R1.2).
- Correction to the measurement above: an idle tunnel isn't silent. udp's idle trace has one 124-byte datagram from device-a 10.0 s after the ping's reply (WireGuard's passive keepalive, KEEPALIVE_TIMEOUT), then nothing from WireGuard until the probe at 450 s; lab/censor/doc.go's claim was right and now cites the trace.
- False positives of reading every size, measured (100 seeds, 6 min of two-way random sizes): sizes 92-404 none flagged at one exchange per 10 s, 1/s, 10/s or 50/s; sizes 40-1500 none at 0.1, 1 and 50 per second, 8 of 100 at 10 per second. HTTP/2 polling every 2 minutes is now flagged, like HTTP/1.1 polling (named risks in lab/censor/doc.go).

## Review findings
Round 1 (2026-11-16; WireGuard's constants confirmed against wireguard-go, oracles real):
- [ ] R1.1 Measure first, offline on the held traces (busy and idle, udp and reality): (a) record-count imbalance per connection, d = n(A→B) − n(B→A), stepping +1 three times 120–210 s apart and flat otherwise; (b) per 2 s ping tick, one extra record each way recurring 120–210 s apart three times. Numbers in Notes whatever they show; no product change, no new rule in the detector this round.
- [ ] R1.2 The reality rhythm cells' detail names the blind spot (and what R1.1 found), never a bare pass.
- [ ] R1.3 checkMatrix requires the udp control row, held and expected to fail, whenever a case holds; TestCheckMatrix covers a matrix without it.
- [ ] R1.4 prober: host dials between probes are a baseline; a nonzero baseline reports "upstream tell: unattributable (N dials between probes)"; a `hosts` entry names at least two addresses.
- [ ] R1.5 holdTunnel checks the hold's pings crossed (busy: under 90% received fails; idle: the one ping) and the idle wait honours ctx.
- [ ] R1.6 Doc honesty: wgPairWindow, wgSteadyJitter and the keepalive count are choices; the 30 s slack and thinkpol's missing persistent keepalive; a tunnel idle over ~90 s between rekeys breaks the chain; the idle passive-keepalive claim reconciled with the trace.
- [ ] R1.7 The idle rhythm case leaves the matrix until the owner rules (holdTunnel's idle branch and its test stay); acceptance boxes reworded so each ticked one is true.
- [ ] R1.8 Nits: tests close the trace file; the trace setting's comment says each line is a synchronous write in the packet path.

## Log
- 2026-11-16 created in backlog (from the M2 gate review)
- 2026-11-16 backlog → in-progress, owner: agent-tp-223
- 2026-11-16 rhythm detector reads every record size and UDP datagrams, thresholds from WireGuard's timers (lab/censor/doc.go); trace setting; idle rhythm case; udp held as the control in both rhythm cases (checkMatrix enforces it); prober `hosts` so reality's tell shows over IPv6; reality's prober cell needs the tell on every probe
- 2026-11-16 mutations, each killed: exchanges only for 92-404-byte records (TestWGRhythmFlagsTheRhythm, floor of 512); UDP datagrams not read (TestWGRhythmDatagrams); prober hosts ignored (TestProberUpstreamTellAcrossHostAddresses); trace not written (TestWGRhythmTrace); exchanges walked in map order (TestWGRhythmFlagsTheRhythm, -count 30); checkMatrix control rule off (TestCheckMatrix)
- 2026-11-16 measured at 02284b57: udp caught in use (240.5 s, rekey), not caught idle (WireGuard silent: no persistent keepalive); reality passes both (all records 507 bytes, path probes every ~1 s); details in Notes
- 2026-11-16 make lint and make test pass at c3d655b0; make lab-test at c3d655b0 fails only on udp × wireguard-rhythm (idle) (the measurement) and TP-220's dns settle flake; two boxes left open for the owner (Notes)
- 2026-11-16 not verified: reality's rekeys themselves (invisible on the wire by design of the floor; udp's held run shows WireGuard rekeying at 120 s and 240 s under the same hold)
- 2026-11-16 in-progress → review
- 2026-11-16 review → in-progress — owner: agent-tp-223, round 1: review findings
- 2026-11-16 review round 1: fix R1.1–R1.8; owner decides the idle promise
