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
stream: verification
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
- [x] R1.1 wireguard-fingerprint's transport rule needs len%16 == 0, but the kernel caps padding at the MTU: a full 1420-MTU packet is 1452 bytes and passes. Match type 4 + three zeros with length >= 32.
- [x] R1.2 ip-blocklist errors say 'destinations' for its 'addresses' key; one parsePrefixes(field, in) helper for both modules, test text fixed.
- [x] R1.3 blockSettings.parse copies block-ip's verdict/rate parsing; block-ip uses the shared code (per-packet, Flow false), one settings-unmarshal helper for every module.
- [x] R1.4 'on any port' is untested: unit positives on port 443, matrix reference rows off the default ports; a 51820-only mutation must fail.
- [x] R1.5 censorCase.blocker is unchecked: check it up front next to the cc.modules == nil check.
- [x] R1.6 WireGuard wire constants in one const block used by wgrhythm.
- [x] R1.7 modules_sniblocklist.go comment: an ECH ClientHello is judged by its outer name.
- [x] R1.8 pin the OpenVPN package version in lab/Dockerfile; ping's 'Network is unreachable' before the tun exists counts as no reply (or a comment says why not).
- [x] R1.9 nits: leading-dot sni names rejected; sni name errors print the raw name and a reason; tests for the key id and retainBytes OpenVPN/sni mutations; clienthello.go version comment; vector8/vector16; ovpnConn state field plus reason; retire → retired; curl exit 35 blocked only on a reset; doc.go Limits names openvpn-fingerprint's per-connection state; doc.go long lines rewrapped.
- [x] R2.1 sni-blocklist: canonicalName trims one trailing dot, so "blocked.example.net.." built as "blocked.example.net." and never matched; a name still ending in "." after canonicalising is a settings error. Settings test case added.
- [x] R2.2 wireguard-fingerprint's false-positive estimate (modules_wireguard.go, doc.go) now says structured UDP matches far more often than random bytes: an iterative DNS query with ID 0x0400, about 1 in 65,536; the rule is unchanged.
- [x] R2.3 vpnpeers_test.go probe comment: blockedBy accepts a drop in either IP family, so the "not scored blocked" guarantee holds for the whole cell, not per family.

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
- 2026-11-08 R1 fixes (continuing after the previous agent stopped on a usage limit; its uncommitted edits reviewed and kept): wireguard-fingerprint matches transport data of 32 bytes or more at any length (R1.1, a 1452-byte full-MTU message is blocked; doc.go's 'caught by its next packet' holds); parsePrefixes(field, in) for block-ip, replay and ip-blocklist (R1.2); block-ip on blockSettings, per packet (decidePacket, Flow false), and every module reads settings through unmarshalSettings (R1.3); unit positives on port 443, the matrix's WireGuard on 443/4443 and OpenVPN on 8443/9443 (R1.4); a censor case that expects a fail names a blocker, checked before any cell runs (R1.5); WireGuard wire constants in lab/censor/wireguard.go, wgrhythm uses them (R1.6); ECH comment (R1.7); lab/Dockerfile pins openvpn=2.6.14-0+deb12u2, the version the lab image ran, and the OpenVPN probe counts ping's 'Network is unreachable' before the tun is up as no reply, the verdict log still having to blame the handshake for a blocked cell (R1.8); R1.9 nits all done
- 2026-11-08 mutation checks, each seen to fail its test and restored: the 16-byte step back (TestWireGuardFingerprint); match on DstPort 51820 only (TestWireGuardFingerprint); parsePrefixes ignoring its field, and its empty-list error (TestIPBlocklistSettings); block-ip pinned to the flow (TestBlockIPDropsByDestination); nil settings unmarshalled (TestModulesWithoutSettings); a leading dot accepted (TestSNIBlocklistSettings); key id unchecked on client[1], and on server[0] (TestOpenVPNFingerprintStrays); sni retiring on an incomplete ClientHello regardless of retainBytes (TestSNIBlocklistOutgrowsPrefix). Not mutation-run: the R1.5 blocker check, the matrix's port move, R1.8's ping and the curl exit 35 rule (lab-only, judged by the matrix run). The old block-ip reset (entry) row stays removed: a UDP reset-as-drop end-to-end check no longer exists (TCP reset: TestTCPResetReachesClient)
- 2026-11-08 make lint, make test green on fc251c5. make lab-test not run to completion: the pinned OpenVPN changes lab/Dockerfile, so the lab image must be rebuilt, and Docker can't reach the registry (a base image pull and both builders hang resolving the base image, past 9 minutes), so the run timed out waiting for the image. TestCensorMatrix with the new ports and lab/RESULTS.md are not re-run. Handoff: once Docker pulls again, run the full make lab-test on the branch head, commit lab/RESULTS.md if it changed, then has-errors → review
- 2026-11-09 has-errors → in-progress (lab run resumed now that Docker pulls again); stream: verification, after merging TP-111's stream key
- 2026-11-09 merged origin/rewrite (TP-111); make lint, make test green on 1879d37
- 2026-11-09 full make lab-test green on 1879d37 (GOFLAGS=-p=2, LAB_P=1): the lab image rebuilt with the pinned openvpn=2.6.14-0+deb12u2; TestCensorMatrix ran complete with WireGuard on 443/4443 and OpenVPN on 8443/9443, the R1.5 blocker check, R1.8's ping rule and the curl exit 35 rule, and regenerated lab/RESULTS.md unchanged (no row moved: the reference rows still fail only their fingerprint module and the ip-blocklist, https (control) still passes both fingerprints). Still not mutation-run: the R1.5 blocker check and the ping and curl exit 35 rules
- 2026-11-09 in-progress → review
- 2026-11-09 delta check: R2.1–R2.3 (nits); R2.1 mutation: dropping the trailing-dot check fails TestSNIBlocklistSettings; go test ./lab/censor/... and make lint green
