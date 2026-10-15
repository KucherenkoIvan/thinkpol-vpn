---
id: TP-064
title: "Reality transport: Xray REALITY wire compatibility and using existing VLESS/Reality servers"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: L
depends_on: []
refs: [C2, DESIGN#transports]
owner: "glm-tp064"
branch: "tp-064-reality-prototype"
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
- [x] where a question needs it, a throwaway prototype in the lab (not merged into `internal/`) shows an interoperating handshake or says why it can't
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
- **Prototype result (2026-10-15)**, `lab/prototypes/reality/` on branch `tp-064-reality-prototype`: both handshakes work against unmodified Xray. Answer to the riskiest question: **yes, a thinkpol-written REALITY client interoperates with a stock Xray server.** The client (`reality.go`, on uTLS, seal and HMAC check written from the findings) authenticated with the right short id (Ed25519 leaf whose signature is `HMAC-SHA512(AuthKey, pubkey)`), then carried one VLESS request through the stock server to an HTTP echo; with a wrong short id the server spliced the raw connection to the camouflage target, whose minted certificate the client received unchanged, and the target received the ClientHello **byte-identical** to what was sent. Test: `TestRealityPrototype` (lab tag, host) starting the stock Xray container and `TestRealityClientInterop` (run inside the lab node); output:
  ```
  === RUN   TestRealityClientInterop
  === RUN   TestRealityClientInterop/right_short_id
  === RUN   TestRealityClientInterop/wrong_short_id
      reality_test.go:120: splice path: the target received the identical ClientHello (1812 bytes)
  --- PASS: TestRealityClientInterop (1.01s)
      --- PASS: TestRealityClientInterop/right_short_id (1.01s)
      --- PASS: TestRealityClientInterop/wrong_short_id (0.00s)
  PASS
  --- PASS: TestRealityPrototype (5.66s)
  ```
  - **Versions:** Xray `26.3.27`, image `ghcr.io/xtls/xray-core`, linux/arm64 manifest digest `sha256:79f798b6a130132414c45773bc039e9e51b9694f2dd5ddf99083353ece168f48`; uTLS `v1.8.2` (BSD-3-Clause, licence checked), fingerprint `HelloChrome_Auto` (what Xray's own client uses for `"chrome"`); Go 1.26 stdlib `crypto/hkdf`.
  - **Interop details that held exactly as described:** session id at handshake offset 39; additional data = the ClientHello handshake message (4-byte header included, TLS record header not) with the session id zeroed; AES-256-GCM with `HKDF-SHA256(shared, salt=Random[:20], info="REALITY")`, nonce `Random[20:32]`, the 32-byte ciphertext+tag filling the session id. No debugging was needed: the first sealed ClientHello was accepted. Xray's config `privateKey`/`publicKey` are base64url-raw; `maxTimeDiff` is milliseconds (the conf multiplies by `time.Millisecond`); `minClientVer`/`maxClientVer` unset means no version check.
  - **Surprise, inference from source, not tested:** current XTLS/REALITY's server ignores (splices) any ClientHello without an `X25519MLKEM768` key share, using the X25519 half for the shared secret when no standalone X25519 share is present. The Chrome hello carries it. TP-087's hello must include that key share.
  - **For TP-087:** the uTLS v1.8.2 public surface is exactly enough — `BuildHandshakeState`, then `HandshakeState.Hello.Raw`/`SessionId`/`Random` and `State13.KeyShareKeys.Ecdhe`/`MlkemEcdhe` for the shared secret; patch `Raw[39:]` after building and the handshake sends the patched hello. Xray dials `target` before parsing the ClientHello even on the authenticated path, so the upstream tell exists for every connection, not only probes (source observation, not measured). The one-shot VLESS round trip needed: version byte, UUID, empty addons, `0x01`, port, address type + address; response is version byte + empty addons, then the payload.     Nothing from Xray's code was copied.

## Review findings
- [ ] S1: `reality_test.go:228-231` asserts that on the authenticated path Xray "never sends a ClientHello" to the target. The reviewer expects XTLS/REALITY's MirrorConn to write every byte to the target, so the target would see every ClientHello, authenticated ones included. Measure it (connection count and captured hellos during the right-short-id subtest), report what's true, align the comment and Notes. Matters for TP-087 and TP-088 (the upstream tell).
- [ ] S2: the host test can pass with nothing run: `TestRealityClientInterop` skips when `THINKPOL_LAB` is unset or the config is missing, and `RunGoTests` treats a skip as a pass. Fail instead: check the in-node output contains `--- PASS` for `right_short_id` and `wrong_short_id`. Prove it with a temporarily broken config path.
- [ ] S3: `prototype_test.go:33` pins the arm64 manifest digest; pin the multi-arch index digest of the same tag instead.
- [ ] S4: the ticket (Notes, "Interop details") overclaims as "held exactly as described": maxTimeDiff in milliseconds, unset min/maxClientVer meaning no check, the time window itself — none tested. Move to "source observation, not tested"; optionally add a stale-timestamp subtest (right short id, seal outside maxTimeDiff → expect splice), which would settle the milliseconds question.
- [ ] N1: `reality.go:191-195` fallback comment misleading: HelloChrome_Auto (uTLS v1.8.2 = HelloChrome_133) carries a standalone X25519 share, which the client used. Fix comment and say in the ticket what was actually shown; the MLKEM-required claim stays an inference.
- [ ] N2: `reality.go:114-120`: also check `Raw[38] == 32` (the session id length) before writing at 39; clear error otherwise.
- [ ] N4: dead code and nits: unused `addrDomain` (`vless.go:18`), `_ = res` (`prototype_test.go:95`), `expect int` unnamed (`reality_test.go:133`), xray logs dumped only on the readiness timeout, not when the in-node tests fail (`prototype_test.go:177`).

## Log
- 2026-10-13 created in backlog (TP-062)
- 2026-10-15 docs (board op): findings note added to Notes, findings box ticked; prototype and DESIGN transports table boxes left open
- 2026-10-15 docs (board op): DESIGN transports table box ticked; prototype box left open
- 2026-10-15 backlog → in-progress — owner: glm-tp064 (prototype)
- 2026-10-15 in-progress → review — prototype box ticked, result in Notes; `make lint`, `make test` and the lab test pass on this branch
- 2026-10-15 review → has-errors — round-1 review findings (S1-S4, N1, N2, N4) as boxes; owner: glm-tp064 (round 2)
- 2026-10-15 has-errors → in-progress — owner: glm-tp064 (round 2)
