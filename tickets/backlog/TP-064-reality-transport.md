---
id: TP-064
title: "Reality transport: Xray REALITY wire compatibility and using existing VLESS/Reality servers"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: L
depends_on: []
refs: [C2, DESIGN#transports]
owner: ""
branch: ""
---

## Goal
A written answer, with a prototype where it helps, to how thinkpol can use REALITY: the owner wants REALITY support and the `reality`-style transport is pulled forward. The `tls` transport's server side can't match its camouflage site's hello and opens an upstream connection per probe (independent design review, 2026-10-13); borrowing a real site's handshake removes both. Research first, then the findings become tickets.

## Scope
Questions to answer:
- **Our transport speaking REALITY.** Can a thinkpol transport speak Xray's REALITY handshake (borrowing a real site's TLS, no certificate of our own), so existing tooling and servers interoperate? What is on the wire, what keys and short ids does it need, and what would the transport's settings, credential and the camouflage target look like in the map?
- **Existing servers as entry or exit.** Can an existing VLESS/Reality server (for example a 3x-ui deployment) act as an entry or exit for thinkpol traffic, with VLESS UDP carrying our frames? What would the node owner configure, and what would the map say about such a node?
- **What is lost** against our own transport: need-to-know sections, per-space isolation and workers, the supervisor's authentication and fair share, traffic shaping (C6), telemetry, anything else.
- Licensing and dependency questions of reusing REALITY's Go code (Xray is Go): what can be vendored or imported, and what must be written again.

## Out of scope
- A **bridge** node type (a VLESS ingress routed into the overlay): considered and set aside as too complex for now. Revisit only if the answers above make it cheap.
- Implementing the transport: a ticket from the findings.

## Acceptance
- [x] a findings note in this ticket's Notes answers each question above, with the recommendation and the follow-up tickets it proposes
- [ ] where a question needs it, a throwaway prototype in the lab (not merged into `internal/`) shows an interoperating handshake or says why it can't
- [x] DESIGN.md's transports table reflects the result

## Notes
- Related: TP-028 (`tls`, whose server-side tells this addresses), TP-026 and TP-032 (the prober that measures them), PRD "Decisions" (Reality).
- **Findings (2026-10-15)**, from a research pass (confidence high on the wire format and licensing, medium on authenticated-session fingerprinting, low on country-specific claims):
  - **Q1, our transport speaking REALITY: yes.** uTLS builds a browser ClientHello; the 32-byte session id (handshake offset 39) seals the Xray version, a Unix time and the 8-byte short id with AES-256-GCM, keyed by HKDF-SHA256 of the X25519 shared secret (client key share × server static key, salt `Random[:20]`, info `"REALITY"`), nonce `Random[20:32]`, additional data the ClientHello with the session id zeroed (the likely interop bug). The server opens it, checks version, time window and short id, and otherwise splices the raw TCP connection to `target`. The client checks an Ed25519 leaf whose signature is `HMAC-SHA512(AuthKey, public key)`; a real certificate means failure. Map: a per-node listener with an X25519 private key, `target` as IP:port and server names; the device `Endpoint` carries SNI, server public key and fingerprint; the credential is the short id, a shared secret. Path frames ride inside the TLS records with C6 shaping; a stock server won't understand them.
  - **Q2, existing VLESS servers:** never an exit (they terminate proxy requests, not WireGuard, and have no overlay). A stock VLESS+REALITY server could only be a dumb UDP pipe in front of a thinkpol node, with `forward_to` in its config; not a node, and out of the first implementation.
  - **Q3, what is lost:** need-to-know sections and per-space workers are kept (short id → space, the established TLS connection handed to the worker). The gatekeeper (TP-063) must hold the listener's X25519 private key, not only verifiers, and a seized entry can impersonate the server to its clients. Replay protection must be built (Xray's default `maxTimeDiff` 0 allows replays): five-minute window, replays spliced. C6 shaping is not provided (Vision pads inner TLS, the wrong fit). Fair share has the usual stream-transport gap. The upstream tell remains.
  - **Q4, licensing:** thinkpol is MIT; Xray-core and XTLS/REALITY are MPL-2.0 (per-file copyleft), uTLS is BSD-3. Import uTLS; never vendor MPL files into the tree under MIT.
  - **Detection state:** the inner protocol is WireGuard, so the TLS-in-TLS fingerprint doesn't apply, but record lengths and the rekey rhythm do (C6). SNI should be plausible for the node's IP and network; a CDN target turns the node into a public forwarder. No measurement of RU or IR; whitelists are not passed by any disguise.
  - **Recommendation:** thinkpol↔thinkpol REALITY as the M2 censor-facing transport on uTLS; `tls` kept for links that can live with our own certificate; stock VLESS only as an optional front, later, never an exit. First lab test: two handshakes against unmodified Xray (right short id verifies, wrong one is spliced to a local target). Proposed tickets: the `reality` transport (TP-087), the gatekeeper learning `reality` (TP-088), and docs.
  - **Decision (2026-10-15):** `reality` is the M2 disguised transport, `tls` (TP-028) moves to after the MVP; see PRD "Decisions" and ORCHESTRATION "Decisions (2026-10-15)".

## Log
- 2026-10-13 created in backlog (TP-062)
- 2026-10-15 docs (board op): findings note added to Notes, findings box ticked; prototype and DESIGN transports table boxes left open
- 2026-10-15 docs (board op): DESIGN transports table box ticked; prototype box left open
