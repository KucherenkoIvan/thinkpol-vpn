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

## Log
- 2026-11-16 created in backlog (from the M2 gate review)
- 2026-11-16 backlog → in-progress, owner: agent-tp-223
