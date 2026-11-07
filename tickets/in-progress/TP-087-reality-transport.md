---
id: TP-087
title: "`reality` transport"
milestone: M2
area: dataplane/transport
repo: thinkpol-vpn
size: L
depends_on: [TP-064, TP-010, TP-027, TP-101]
refs: [C2, C6, docs/design/transports.md#transports]
owner: "agent-tp-087"
branch: "tp-087-reality-transport"
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
- `reality` uses only the public transport contract (docs/design/transports.md, Plugins); the transport boundary counts as the wire.

## Out of scope
- VLESS and Vision: stock VLESS clients and servers are not supported.
- Moving the session-id open into the gatekeeper: TP-088.
- The `tls` transport: TP-028, after the MVP.

## Acceptance
- [x] the depend-or-reimplement decision is recorded in Notes, with the MPL rules above respected
- [ ] a two-handshake lab test against stock Xray: the right short id verifies; a wrong one is spliced to the target
- [ ] passes the TP-005 conformance suite with shaping on and off
- [ ] the censor-lab matrix has rows for `reality`

## Notes
- Findings and wire format: TP-064 Notes. Decision: PRD "Decisions" (2026-10-15), docs/design/transports.md.
- From TP-101's review (2026-10-19): the five-minute skew window (`maxClockSkew`) and the wrap-safe `sentFresh` live in udp/wire.go; move them to the transport port before building reality's replay checks on copies of them.
- At M2, `reality` must pass the lab's handshake-level checks and show no WireGuard rhythm (2-minute rekey pair, fixed-size keepalive records inside TLS); flow shape beyond that is not tested at M2 (owner, 2026-11-07). If it fails TP-188's check with default settings, the fix is a minimal padding/batching default, not a full shaping module.
- The wireguard-rhythm cell's probe runs for at least two WireGuard rekey periods (up to about 7 minutes; up to about 10 minutes when the transport batches records; see lab/censor/doc.go) with the transport's default settings, so a pass means the rhythm was looked for (a ~30 s probe passes trivially)
- **Decision: depend on XTLS/REALITY, unmodified (owner, 2026-11-07, the orchestrator's default; recorded by the implementer).** The server side is `github.com/xtls/reality` as a Go module dependency, never copied, vendored or patched: its files are MPL-2.0 (per-file copyleft) and this tree is MIT, so they stay in the module cache and are used only through the package's exported API (`reality.Server`, `reality.Config`, `Conn.ClientShortId`). Why depend rather than reimplement: REALITY's server is a fork of Go's crypto/tls that imitates the target's ServerHello record by record; a reimplementation would be a second TLS stack to keep in step with upstream's probe-resistance fixes. Checked as a library (2026-11-07): `reality.Server(ctx, conn, cfg)` takes any `net.Conn` that also has `CloseWrite` (it type-asserts that, so a wrapper replaying bytes already read must implement it), dials the target itself through `Config.DialContext`, splices whatever fails its own check, and reports the opened short id; `DetectPostHandshakeRecordsLens(cfg)` must be called first when its own listener isn't used.
  - **Pinned at commit 8cdf7bf (2026-09-08), pseudo-version `v0.0.0-20260908062103-8cdf7bf9c7f0`:** the newest commit whose go.mod says `go 1.24.0`; every later one says `go 1.27`, and this repo's toolchain is go1.26.10. It includes the 2026-09-08 fixes (post-handshake record detection panic, leak and race) and the rule that a ClientHello without an X25519MLKEM768 share before any standalone X25519 share is spliced (the client's Chrome hello has both, in that order). Moving to a later commit means moving the toolchain to Go 1.27 first.
  - **What it pulls in:** `cloudflare/circl` (BSD-3), `juju/ratelimit` (LGPL-3 with a static-linking exception: no source or relinking obligation for the combined binary while the library is unmodified), `pires/go-proxyproto` (Apache-2.0), plus uTLS (BSD-3), already here. Build-checked for darwin, linux, windows and android/arm64 with CGO_ENABLED=0 on go1.26.10.
  - **Side effect:** the package's `init` makes an Ed25519 key and two self-signed certificates in every binary that links it (milliseconds at start).
  - **The client is ours,** on uTLS: the seal and the HMAC certificate check are written from the protocol description in TP-064's Notes, not from REALITY's code; Xray-core is not a dependency.
  - **The router's open is ours too:** a shared listener must tell the space from the ClientHello before any TLS is terminated, and the replay cache needs the sealed session id, so the supervisor-side router opens the session id itself (same rules: key share choice, HKDF, AES-GCM) and only then hands the connection to `reality.Server` in the worker. Both say no → both splice.

## Log
- 2026-10-15 created in backlog (TP-064 findings)
- 2026-10-19 Notes: move udp's skew window and sentFresh to the port first (TP-101 review round 2)
- 2026-11-07 docs: scope: only the public transport contract; the boundary counts as the wire (owner, 2026-11-07)
- 2026-11-07 notes: what passing the M2 gate means (owner, 2026-11-07)
- 2026-11-07 rhythm-cell probe length added (from TP-188's reviews)
- 2026-11-07 rhythm probe length corrected after TP-188 merged
- 2026-11-07 backlog → in-progress, owner: agent-tp-087
- 2026-11-07 decision recorded: depend on XTLS/REALITY unmodified, pinned at 8cdf7bf (newest go 1.24 commit; later ones need Go 1.27)
