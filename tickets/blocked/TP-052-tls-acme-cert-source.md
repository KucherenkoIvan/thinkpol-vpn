---
id: TP-052
title: "ACME certificate source for `tls`"
milestone: later
area: dataplane/transport
repo: thinkpol-vpn
size: M
depends_on: [TP-028]
refs: [C2, DESIGN#transports]
owner: ""
branch: ""
---

## Goal
A `tls` node can serve a real, publicly trusted certificate for an ordinary-looking domain, so a prober sees honest TLS instead of the self-signed certificate of TP-028's first adapter.

## Scope
- A second adapter for the certificate source port from TP-028: ACME (e.g. Let's Encrypt), with issuance and renewal on the node.
- Per-node domain in the node's transport settings; the client verifies the certificate normally instead of pinning it.
- Domains must look ordinary and be rotatable: the domain is visible in SNI and can be blocked by name.

## Out of scope
- Registering domains or managing DNS records automatically.
- The `reality`-style transport (no certificate of our own): a separate later transport.

## Acceptance
- [ ] a lab node gets and renews a certificate through the ACME adapter (against a test ACME server such as Pebble in the lab)
- [ ] the lab matrix shows the prober result for `tls` with the ACME adapter next to the self-signed one

## Blocked by
The author has no domain. Needs a domain (or several, for rotation) and a registrar to buy them from; only the author can provide them.

## Notes
- **Optional now (TP-005 review, 2026-10-10):** probes are proxied whole to the camouflage target and see the real site's certificate (DESIGN.md), so the node's own certificate is only ever seen by authenticated clients that pin it. An ACME certificate no longer fixes a prober-visible weakness; keep this only if a real certificate is wanted for other reasons.

## Log
- 2026-10-10 created in blocked
