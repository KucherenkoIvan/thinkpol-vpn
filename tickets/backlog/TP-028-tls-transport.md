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
- **Certificate source port** inside `transport/tls`: where the server's certificate comes from is a pluggable port, not hard-wired. First adapter: a **self-signed certificate pinned by the client** (the pin travels with the link credential in the map), used in the lab and tests.

## Out of scope
- ACME (real domain) certificate source: TP-052.
- Borrowing a real site's handshake: the later `reality`-style transport.

## Acceptance
- [ ] passes the TP-005 conformance suite with shaping on and off
- [ ] a probe without credentials gets the camouflage site, byte for byte
- [ ] the client's JA3/JA4 matches the targeted browser
- [ ] the server certificate comes through the certificate source port; the self-signed adapter generates a certificate, and the client rejects any certificate that doesn't match its pin

## Notes
- **Decided in the TP-005 review (2026-10-10):** the tls auth token rides in the ClientHello (e.g. an HMAC of the credential and a coarse timestamp in the legacy session id, via uTLS). The supervisor peeks at the ClientHello without terminating TLS and keeps a replay cache. Authenticated: it hands the fd plus the consumed bytes to the space's worker, which terminates TLS with its self-signed, pinned certificate. Anything else is proxied whole to the camouflage target, so probes see the real site's certificate. See DESIGN.md (transports table, server agent). This replaces "authentication inside the first application data" in Scope; the probe fallback proxies the whole connection, ClientHello included.
- **Port (TP-005):** implement `transport.Transport` and `transport.Routable` (`RouteStream` peeks the ClientHello and returns the consumed bytes). The worker side is a `transport.HandoffListener`. Settings go in `proto/thinkpol/transport/v1/` as tls messages; the pin can travel there or in the credential. Run `transporttest.Run` with restart support, and with `Interpose` if you can replay a TCP stream.
- **Blocker resolved (2026-10-10):** the author has no domain and no valid TLS certificate. Decision: the certificate comes from a pluggable certificate source port; the first adapter is self-signed and pinned by the client (option (c) of the original blocker). ACME with a real domain (option (a)) is TP-052, blocked until a domain and registrar exist; the `reality`-style transport (option (b)) stays a later transport.
- **Known weakness:** a prober that completes the handshake sees a self-signed certificate, which is suspicious on its own. The lab matrix (`lab/RESULTS.md`) must show this honestly, not hide it: if the active prober flags self-signed certificates, `tls` with this adapter fails that row until the ACME adapter exists. PRD's success criterion ("`tls` passes everything except whitelist mode") may not hold with this adapter alone.
- **From TP-010 (tls):**
  - Implement `transport.StreamRoutable`. `ListenStream` opens the public TCP listener. `Router(peers).RouteStream` peeks at the ClientHello and must return **every** byte it read: they go to the worker, or to the camouflage, which proxies them first. `Router.Rejected` reports unusable links. `Handoff(cfg)` is the worker's `HandoffListener`; `SharedListener.Listen` feeds it the handed-over connections.
  - The supervisor's routing deadline is 10 s, with at most 1024 connections being routed per listener. The camouflage proxy is the listener's `Camouflage.Stream`; it must not block, so it starts its own goroutine.
  - Add the lab test of a handoff through real workers that TP-010 couldn't.

## Log
- 2026-10-10 created in blocked
- 2026-10-10 blocked → backlog — certificate source decided: pluggable port, self-signed pinned adapter first (see Notes)
- 2026-10-11 docs (TP-010 review): notes from the shared listener
