---
id: TP-250
title: "udp × fully-encrypted scores its known exemption chance from logged evidence"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-236]
refs: []
needs_human: decision
owner: ""
branch: ""
---

## Goal
The owner wants a full lab to take at most 15 minutes on the remote runner (2026-11-16); after the lab-speed tickets the default stream still took ~36 minutes (TP-239's measurement, 2026-11-19). TP-236 found the GFW's fully-encrypted rules exempt a new flow by chance (~1/175 for a first 84-byte datagram being more than half printable; ~1/383 for udp's printable connection id), and a real censor judges each new client/server pair afresh, so the udp control row honestly crosses about 1 in 120 runs.

## Scope
- The matrix accepts a partial for this cell only when the verdict log shows every crossing flow was the first judged on its client/server pair and was passed by a named exemption (logged by TP-236's R1.7); anything else still fails.
- Document the known chance in RESULTS.md.

## Out of scope
Padding udp's first datagram: rejected (changes the shipped transport for a lab artifact and can't remove the connection-id chance).

## Acceptance
- [ ] The owner's decision recorded (owner, date).
- [ ] The cell's scoring reads the logged exemption; a crossing without it still fails (test with a forged log).
- [ ] RESULTS.md documents the known chance for this cell.

## Notes
- Option chosen by default (orchestrator, pending the owner's yes): scoring from the logged exemption, as in Scope. Rejected: padding udp's first datagram (see Out of scope).

## Log
- 2026-11-19 created in backlog (lab-speed follow-ups)
