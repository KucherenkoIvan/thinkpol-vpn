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
- [ ] The detector flags the rekey pair by timing at any record size; thresholds cited from WireGuard's timers in lab/censor/doc.go.
- [ ] Control: plain WireGuard (`udp`) is caught on a busy tunnel and on an idle one.
- [ ] A new idle-tunnel case in the matrix exercises the keepalive claim.
- [ ] `reality`'s result on both cases measured at this branch's head and recorded in Notes, pass or fail.
- [ ] The reality × prober cell fails unless every failed probe over IPv4 shows a dial to the camouflage target (count equals probes); IPv6's 0 of n is fixed or explained with its cause in the cell.
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
- False positives of reading every size, measured (100 seeds, 6 min of two-way random sizes): sizes 92-404 none flagged at one exchange per 10 s, 1/s, 10/s or 50/s; sizes 40-1500 none at 0.1, 1 and 50 per second, 8 of 100 at 10 per second. HTTP/2 polling every 2 minutes is now flagged, like HTTP/1.1 polling (named risks in lab/censor/doc.go).

## Log
- 2026-11-16 created in backlog (from the M2 gate review)
- 2026-11-16 backlog → in-progress, owner: agent-tp-223
