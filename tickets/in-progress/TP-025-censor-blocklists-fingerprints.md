---
id: TP-025
title: "Censor modules: blocklists and VPN fingerprints"
milestone: M2
area: lab/censor
repo: thinkpol-vpn
size: M
depends_on: [TP-024, TP-064, TP-089]
refs: [C4]
owner: "agent-tp-025"
branch: "tp-025-censor-blocklists"
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
- 2026-10-15 depends_on TP-089 (split from TP-024 review)
- 2026-11-07 backlog → in-progress, owner: agent-tp-025
- 2026-11-07 mutation checks, each seen to fail its test and restored: ClientHello read from one record only (TestClientHelloServerName, TestSNIBlocklistSplitClientHello); ip-blocklist checks the destination only (TestIPBlocklistEitherEnd); sni-blocklist matches exact names only, and retires on an incomplete ClientHello (TestSNIBlocklistSplitClientHello); wireguard-fingerprint without the 16-byte step, and without transport data (TestWireGuardFingerprint); openvpn-fingerprint without the session id check, and without the server's reset check (TestOpenVPNFingerprintStrays), and without retransmission dedup (TestOpenVPNFingerprintUDP)
