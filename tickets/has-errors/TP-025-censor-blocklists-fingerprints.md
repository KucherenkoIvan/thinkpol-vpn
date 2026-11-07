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
- [x] real WireGuard and OpenVPN connections are blocked
- [x] plain HTTPS to an unlisted site passes

## Review findings
- [ ] R1.1 wireguard-fingerprint's transport rule needs len%16 == 0, but the kernel caps padding at the MTU: a full 1420-MTU packet is 1452 bytes and passes. Match type 4 + three zeros with length >= 32.
- [ ] R1.2 ip-blocklist errors say 'destinations' for its 'addresses' key; one parsePrefixes(field, in) helper for both modules, test text fixed.
- [ ] R1.3 blockSettings.parse copies block-ip's verdict/rate parsing; block-ip uses the shared code (per-packet, Flow false), one settings-unmarshal helper for every module.
- [ ] R1.4 'on any port' is untested: unit positives on port 443, matrix reference rows off the default ports; a 51820-only mutation must fail.
- [ ] R1.5 censorCase.blocker is unchecked: check it up front next to the cc.modules == nil check.
- [ ] R1.6 WireGuard wire constants in one const block used by wgrhythm.
- [ ] R1.7 modules_sniblocklist.go comment: an ECH ClientHello is judged by its outer name.
- [ ] R1.8 pin the OpenVPN package version in lab/Dockerfile; ping's 'Network is unreachable' before the tun exists counts as no reply (or a comment says why not).
- [ ] R1.9 nits: leading-dot sni names rejected; sni name errors print the raw name and a reason; tests for the key id and retainBytes OpenVPN/sni mutations; clienthello.go version comment; vector8/vector16; ovpnConn state field plus reason; retire → retired; curl exit 35 blocked only on a reset; doc.go Limits names openvpn-fingerprint's per-connection state; doc.go long lines rewrapped.

## Log
- 2026-10-10 created in backlog
- 2026-10-15 depends_on TP-089 (split from TP-024 review)
- 2026-11-07 backlog → in-progress, owner: agent-tp-025
- 2026-11-07 mutation checks, each seen to fail its test and restored: ClientHello read from one record only (TestClientHelloServerName, TestSNIBlocklistSplitClientHello); ip-blocklist checks the destination only (TestIPBlocklistEitherEnd); sni-blocklist matches exact names only, and retires on an incomplete ClientHello (TestSNIBlocklistSplitClientHello); wireguard-fingerprint without the 16-byte step, and without transport data (TestWireGuardFingerprint); openvpn-fingerprint without the session id check, and without the server's reset check (TestOpenVPNFingerprintStrays), and without retransmission dedup (TestOpenVPNFingerprintUDP)
- 2026-11-07 done: ip-blocklist, sni-blocklist (ClientHello read from the reassembled stream: split over TCP segments, out of order, or over TLS records is read whole), wireguard-fingerprint and openvpn-fingerprint in lab/censor; the matrix gains an https control row and real kernel WireGuard and OpenVPN (udp, tcp) reference rows, one tunnel per underlay family, OpenVPN from the lab image's Debian package. lab/RESULTS.md: wireguard (reference) fails wireguard-fingerprint, openvpn-udp/-tcp (reference) fail openvpn-fingerprint, https (control) passes every module except the blocklists naming it; each blocked cell checks the verdict log blames its module
- 2026-11-07 thinkpol's udp transport passes wireguard-fingerprint: nothing on its wire looks like WireGuard (C1, TestM0); its M2 failure is left to TP-026's fully-encrypted heuristics. Not verified: ECH (inner name unread, documented), the lab matrix's new rows were not mutation-checked beyond their off/blocked contrast
- 2026-11-07 make lint, make test green; full make lab-test green on f63235a
- 2026-11-07 in-progress → review
- 2026-11-07 review → has-errors (round 1 findings R1.x)
