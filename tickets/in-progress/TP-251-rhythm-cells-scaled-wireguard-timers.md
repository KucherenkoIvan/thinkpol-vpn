---
id: TP-251
title: "The rhythm cells run with WireGuard's timers sped up in the lab"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: M
depends_on: []
refs: [RR65]
owner: "agent-tp-251"
branch: "tp-251-scaled-wg-timers"
---

## Goal
The matrix's wireguard-rhythm cells hold the tunnel 7.5 minutes of real time to see three rekeys (the reality and udp rows): the largest fixed wait left in a full lab. The owner's rule (2026-11-16): waits use a sped-up clock wherever possible. A system-wide fake clock can't reach a Go binary (libfaketime hooks libc; time namespaces only offset clocks), but the WireGuard these cells exercise is thinkpol's userspace wireguard-go, whose rekey timers are compile-time constants (device/constants.go).

## Scope
- A lab-only build replaces that constants file with timers scaled by a factor (e.g. 10×) through `go build -overlay`, never touching go.mod or the product binary.
- The censor's rhythm rules (its windows, "the last 2m0s apart", the quiet read) scale by the same factor, from one setting.
- The scaled cells run in every lab.
- One real-timer run of the rhythm cells stays as its own target (`make lab-test-rhythm-real` or similar), run at milestone gates and whenever transport shaping or the rhythm rules change.

## Out of scope

## Acceptance
- [ ] The lab binary's WireGuard rekeys at the scaled interval (lab log), the product binary's doesn't (test).
- [ ] The scaled rhythm cells give the same verdicts as the real-timer run (RESULTS.md diff), and the real-timer target exists and passes.
- [ ] The matrix's long stream (or its replacement) wall time before and after, in Notes.

## Notes
- Only WireGuard's timers scale. Reality's own timing, TCP retransmits, thinkpol's path probes and the traffic generator keep real time, so the noise around each rekey shrinks relative to the interval, and a scaled cell can detect more easily than a real censor would. That is harmless for today's expected-fail cells, but a cell expected to pass (e.g. after TP-237's cover records) must be judged on the real-timer run.

## Log
- 2026-11-19 created in backlog (owner: sped-up clocks wherever possible)
- 2026-11-19 depends_on TP-239 dropped: TP-251 no longer waits on it (TP-239 merges this in)
- 2026-11-19 backlog → in-progress, owner: agent-tp-251
