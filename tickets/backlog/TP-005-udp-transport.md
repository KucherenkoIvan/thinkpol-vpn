---
id: TP-005
title: "Transport port and udp transport"
milestone: M0
area: dataplane/transport
repo: thinkpol-vpn
size: M
depends_on: [TP-001]
refs: [C1, C3, C6, DESIGN#transports]
owner: ""
branch: ""
---

## Goal
The contract every transport implements, and the plain `udp` baseline that the lab is supposed to catch.

## Scope
- Port in `internal/dataplane/transport`: `Listener` (accepts an authenticated `Link` plus the peer's identity: space id, node id), `Dialer` (`Dial(endpoint, credential) → Link`), `Link` (packet-oriented read/write, close, address metadata), credentials per link as given by the map.
- The listener validates credentials before revealing anything; unauthenticated traffic goes to a `Camouflage` handler (for `udp`: drop silently).
- Placeholder in the contract for shaping (filled by TP-027).
- `udp` adapter: payload obfuscated with the link key so WireGuard headers never appear on the wire (C1; sizes still leak, that's what the lab should catch); keyed connection id plus authenticator, so the shared listener (TP-010) can demultiplex without decrypting; replay window.
- Conformance test suite every transport must pass (in-memory and loopback): delivery, behaviour on bad credentials, small and large packets, many concurrent links.

## Acceptance
- [ ] `udp` passes the conformance suite
- [ ] a capture of `udp` traffic carrying WireGuard shows no WireGuard message headers
- [ ] the port is documented in the package doc

## Log
- 2026-10-10 created in backlog
