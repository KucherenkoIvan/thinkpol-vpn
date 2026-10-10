---
id: TP-028
title: "`tls` transport with probe fallback"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: L
depends_on: [TP-010, TP-027]
refs: [C2, DESIGN#transports]
owner: ""
branch: ""
---

## Goal
The workhorse transport: looks like a browser talking to a website, and is a website to anyone without credentials.

## Scope
- Client: uTLS with a current browser fingerprint (Chrome), ALPN `h2`/`http/1.1`.
- Server: TLS 1.3. Authentication inside the first application data: HMAC over the link credential and a timestamp, replay-protected.
- Unauthenticated or failed connections are proxied transparently, as a whole, to the camouflage target.
- Packets framed inside the TLS stream; passes the conformance suite and supports shaping.

## Acceptance
- [ ] passes the TP-005 conformance suite with shaping on and off
- [ ] a probe without credentials gets the camouflage site, byte for byte
- [ ] the client's JA3/JA4 matches the targeted browser

## Blocked by
**Where the server certificate comes from** (a decision for the author):
- **(a) a real domain per node with an ACME certificate.** Honest TLS and simple; the node serves (or proxies) a real-looking site. The domain is visible in SNI and can be blocked by name, so domains must look ordinary and be rotatable. Needs domains.
- **(b) no certificate of our own, borrowing a real site's handshake.** That's the Reality-style transport, listed as later because it's much more work.
- **(c) self-signed, pinned by the client.** The prober sees a self-signed certificate, which is suspicious on its own.

Recommendation: (a) now, (b) as a later transport. Also needed: do you have domains for this, and under which registrar?

## Log
- 2026-10-10 created in blocked
