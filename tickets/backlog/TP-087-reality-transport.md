---
id: TP-087
title: "`reality` transport"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: L
depends_on: [TP-064, TP-010, TP-027, TP-101]
refs: [C2, C6, docs/design/transports.md#transports]
owner: ""
branch: ""
---

## Goal
The disguised transport for client → entry links: thinkpol speaks REALITY's handshake, so a node borrows a real site's TLS and anyone without a valid short id is spliced to that site.

## Scope
- Decided first: depend on XTLS/REALITY's server as an unmodified Go module, or reimplement it. XTLS/REALITY and Xray-core are MPL-2.0: usable as unmodified module dependencies, but their files are never copied into this tree under MIT. uTLS (BSD-3) is imported.
- Client: a uTLS browser ClientHello, the session-id seal (short id and time sealed under the X25519-derived key, additional data the ClientHello with the session id zeroed), and the HMAC certificate check; a real certificate is a failure.
- Server: opens the session id; anything that fails is spliced, raw and whole, to the target's IP:port.
- The short id selects the space; the established TLS connection is handed to the space's worker.
- Path frames inside the TLS records, with C6 shaping, or the link is refused.
- Settings in the map: messages in `proto/thinkpol/transport/v1/` (listener: X25519 private key, target IP:port, server names, time window; device endpoint: SNI, server public key, fingerprint; credential: the short id).
- A five-minute skew window; replays are spliced to the target like any failed auth.

## Out of scope
- VLESS and Vision: stock VLESS clients and servers are not supported.
- Moving the session-id open into the gatekeeper: TP-088.
- The `tls` transport: TP-028, after the MVP.

## Acceptance
- [ ] the depend-or-reimplement decision is recorded in Notes, with the MPL rules above respected
- [ ] a two-handshake lab test against stock Xray: the right short id verifies; a wrong one is spliced to the target
- [ ] passes the TP-005 conformance suite with shaping on and off
- [ ] the censor-lab matrix has rows for `reality`

## Notes
- Findings and wire format: TP-064 Notes. Decision: PRD "Decisions" (2026-10-15), docs/design/transports.md.
- From TP-101's review (2026-10-19): the five-minute skew window (`maxClockSkew`) and the wrap-safe `sentFresh` live in udp/wire.go; move them to the transport port before building reality's replay checks on copies of them.

## Log
- 2026-10-15 created in backlog (TP-064 findings)
- 2026-10-19 Notes: move udp's skew window and sentFresh to the port first (TP-101 review round 2)
