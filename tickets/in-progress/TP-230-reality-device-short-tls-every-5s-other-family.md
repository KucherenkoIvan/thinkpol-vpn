---
id: TP-230
title: "A reality device opens a short TLS connection every ~5 s on the other address family"
milestone: M2
area: dataplane/transport/reality
stream: transports
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-230"
branch: "tp-230-reality-tls-every-5s"
---

## Goal
During the censor matrix's reality holds (TP-223's runs, 2026-11-16), device-a opened about 92 short TLS connections to the server's port 443 over IPv4, one every ~5 s, each completing a handshake and closing, while the link itself rode IPv6. A fixed 5-second pattern of short handshakes is a fingerprint a censor on the path can see. Find what opens them (path probing of the other family, a dial loop, a health check) and decide whether it is needed.

## Scope
- Find the code that opens these connections, with evidence from a lab hold.
- Propose to the owner whether to remove or reshape the pattern, or accept it as a residual risk.

## Out of scope
- Any product change before the owner has seen the fix's scope.

## Acceptance
- [ ] The code that opens these connections named in Notes, with the evidence (a capture or the trace from a lab hold).
- [ ] Either the pattern is removed or changed so it no longer forms a fixed short-handshake rhythm, with a lab check that would catch it coming back, or the owner accepts it as a residual risk with a RESIDUAL-RISKS.md row.

## Notes
- Investigation first; the fix's scope goes to the owner before any product change.

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
- 2026-11-16 backlog → in-progress, owner: agent-tp-230
