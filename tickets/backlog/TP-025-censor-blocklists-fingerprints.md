---
id: TP-025
title: "Censor modules: blocklists and VPN fingerprints"
milestone: M2
area: lab/censor
repo: thinkpol-vpn
size: M
depends_on: [TP-024, TP-064]
refs: [C4]
owner: ""
branch: ""
---

## Goal
The lab blocks what real censors block first: listed IPs and SNIs, WireGuard and OpenVPN.

## Scope
- IP blocklist; SNI blocklist (TLS ClientHello parsing).
- WireGuard fingerprint: message type byte plus three zero bytes, fixed handshake sizes (148/92), cookie replies.
- OpenVPN fingerprint: opcode patterns of the handshake.
- Validated against real WireGuard and OpenVPN running in the lab.

## Acceptance
- [ ] real WireGuard and OpenVPN connections are blocked
- [ ] plain HTTPS to an unlisted site passes

## Log
- 2026-10-10 created in backlog
