---
id: TP-087
title: "`reality` transport"
milestone: M2
area: dataplane/transport
stream: transports
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
The adapter: the client, a standalone listener, the conformance suite and a lab check against stock Xray. Reality behind a server node's shared listener, in the map and in the censor matrix is TP-201 (split 2026-11-08, owner-approved).
- Decided first: depend on XTLS/REALITY's server as an unmodified Go module, or reimplement it. XTLS/REALITY and Xray-core are MPL-2.0: usable as unmodified module dependencies, but their files are never copied into this tree under MIT. uTLS (BSD-3) is imported.
- Client: a uTLS browser ClientHello, the session-id seal (short id and time sealed under the X25519-derived key, additional data the ClientHello with the session id zeroed), and the HMAC certificate check; a real certificate is a failure.
- A standalone listener: opens the session id; anything that fails is spliced, raw and whole, to the target's IP:port; an authenticated hello's TLS handshake is REALITY's server.
- A five-minute skew window; replays are spliced to the target like any failed auth.
- Path frames inside the TLS records, with C6 shaping, or the link is refused.
- The settings messages in `proto/thinkpol/transport/v1/` (listener: X25519 private key, target IP:port, server names, time window; device endpoint: SNI, server public key, fingerprint; credential: the short id).
- The TP-005 conformance suite, with shaping on and off.
- A lab check: our dialer against stock Xray's REALITY inbound, pinned by version and digest, with the target a site in the lab (no internet at test time).
- `reality` uses only the public transport contract (docs/design/transports.md, Plugins); the transport boundary counts as the wire.

## Out of scope
- VLESS and Vision: stock VLESS clients and servers are not supported.
- `reality` behind the shared listener (the supervisor-side router, the short id selecting the space, the handoff to the space's worker), the agent's transport registry and `thinkpol dev map` support, the lab camouflage-target container, the censor-matrix rows: TP-201.
- Moving the session-id open into the gatekeeper: TP-088.
- The `tls` transport: TP-028, after the MVP.

## Acceptance
- [x] the depend-or-reimplement decision is recorded in Notes, with the MPL rules above respected
- [x] a two-handshake lab test against stock Xray: the right short id verifies; a wrong one is spliced to the target
- [x] passes the TP-005 conformance suite with shaping on and off
- [x] the standalone listener splices a wrong short id and a replay to the target raw and whole and refuses a hello sealed outside its time window; the dialer fails on a real certificate (unit tests)

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

- **Proposed split (implementer, 2026-11-07):** this branch is the adapter: the client, a standalone listener, the conformance suite and the stock-Xray check. The rest is a ticket of its own (TP-087b, for the board to file): (1) `reality` as a `transport.StreamRoutable`: the supervisor-side router opens the session id and keeps the replay cache, and the worker's `HandoffListener` runs REALITY's server, which needs the listener's settings in the shared-listener IPC message (supervisor and worker packages); (2) the agent's transport registry and `thinkpol dev map` spec support for reality endpoints and keys; (3) a lab camouflage-target container TP-026 can point its prober at; (4) the censor-matrix rows, the wireguard-rhythm cell probed for two rekey periods with default settings included, and a minimal padding default if it fails. Matrix rows need all of (1)–(3): a server node always serves through the supervisor. Approved by the owner on 2026-11-08 and filed as TP-201.
- **What the lab check covers:** our dialer against stock Xray 26.3.27's REALITY inbound (right short id: Xray's certificate proves its key; wrong one: spliced raw and whole to a target site in the lab node, whose certificate fails the dial). Our listener is checked against our dialer only (unit tests and the conformance suite), not against a stock Xray client.

## Review findings
Round 1 (2026-11-07):
- [ ] R1.1 (blocker) timing distinguisher: the target is dialled only after the whole first record arrived (up to 10 s), so a stalling prober sees the close ~10 s later than at the real site. Dial the target at accept and forward each chunk as it is read, as upstream does; hand that same target connection to REALITY for a hello that authenticates.
- [ ] R1.2 the replay cache is global: one short id sending fresh hellos fills it and locks every other client out for the window. A per-short-id share; future-dated seals must not block eviction for others.
- [ ] R1.3 a splice whose one direction ended blocks forever on a silent client, and Close doesn't end live splices: a short read deadline on the other direction, Close ends them.
- [ ] R1.4 detect: an unreachable or stalled target leaves REALITY with no records learned (or looping in 5 s sleeps for every authenticated connection). Listen fails when the records weren't learned; a test pins the key format against the pinned module; detect is a plain function.
- [ ] R1.5 docs and comments: Options.Control, the Notes' list of upstream APIs, "planned stream transports", registry's nil Camouflage, go.mod pin comment, doc.go (in-memory replay cache, REALITY's real clock), go mod tidy.
- [ ] R1.6 duplication: one shaping bounds helper in the port for udp and reality; one checkDial for CheckEndpoint and Dial.
- [ ] R1.7 a refused entry sharing a short id with a valid one leaves the valid one in the table.
- [ ] R1.8 tests: t.Helper in fixture helpers, theTarget fails each caller on a setup error, behaviour-sentence test names, a test telling our freshness gate apart from REALITY's MaxTimeDiff; nits.

## Log
- 2026-10-15 created in backlog (TP-064 findings)
- 2026-10-19 Notes: move udp's skew window and sentFresh to the port first (TP-101 review round 2)
- 2026-11-07 docs: scope: only the public transport contract; the boundary counts as the wire (owner, 2026-11-07)
- 2026-11-07 notes: what passing the M2 gate means (owner, 2026-11-07)
- 2026-11-07 rhythm-cell probe length added (from TP-188's reviews)
- 2026-11-07 rhythm probe length corrected after TP-188 merged
- 2026-11-07 backlog → in-progress, owner: agent-tp-087
- 2026-11-07 decision recorded: depend on XTLS/REALITY unmodified, pinned at 8cdf7bf (newest go 1.24 commit; later ones need Go 1.27)
- 2026-11-07 udp's maxClockSkew and sentFresh moved to the port as transport.MaxClockSkew and transport.FreshUnix, no behaviour change; new TestFreshUnix (mutations: the lower bound widened to 2×skew, the mod-2^32 distance read unsigned: both fail it); make lint and make test green
- 2026-11-07 picked up after the pause: kept the paused session's adapter (reviewed against upstream REALITY's server: same key-share rule, same seal) and committed it; added a 15 s bound on REALITY's handshake, which has none of its own
- 2026-11-07 conformance suite passes with shaping off, padded to buckets and at random (TestConformance, TestConformanceShaped); the suite's restart test now accepts a stream link that closes instead of delivering
- 2026-11-07 reality tests and their mutations: wrong short id and replay spliced raw and whole to the target (splice without the consumed bytes, the replay check removed: both fail), a real certificate fails the dial (the certificate check skipped; the HMAC not checked: TestProvesKey), the time window (window setting ignored), the key-share rule (an X25519 share without X25519MLKEM768 taken), seal and open (additional data keeping the session id), padding frames (one-byte pad dropped), replay-cache expiry (no eviction): each fails its test
- 2026-11-07 lab: TestRealityStockXray (stock Xray 26.3.27 pinned by digest, target site in the lab node, no internet) passes; mutation: the seal keyed from the X25519MLKEM768 half instead of the standalone X25519 share fails its right-short-id subtest
- 2026-11-07 docs: reality package doc, DESIGN.md index row, transports.md reality paragraph, transport doc's stream section
- 2026-11-07 matrix rows not done: they need reality behind the shared listener, map and registry support and a lab target container; proposed split in Notes (TP-087b)
- 2026-11-08 merged origin/rewrite; split approved by the owner: Scope and Acceptance narrowed to the adapter, the censor-matrix box moved to TP-201; stream: transports
- 2026-11-08 listener and dialer box ticked on f28d41e + board edits: TestWrongShortIDIsSplicedToTheTarget, TestReplayIsSplicedToTheTarget, TestTimeWindow, TestProvesKey, TestConformance, TestConformanceShaped pass (go test -count=1 ./internal/dataplane/transport/reality/; mutations in the 2026-11-07 lines); make lint and make test green
- 2026-11-08 lab: make lab-gotest PKG=./lab RUN=TestRealityStockXray passes (both in-node subtests, right and wrong short id, passed); full make lab-test (GOFLAGS=-p=2, LAB_P=1) green on b5b30df
- 2026-11-08 not verified here: our listener against a stock Xray client (dialer-side only, see Notes); everything behind the shared listener and the matrix is TP-201
- 2026-11-08 in-progress → review
- 2026-11-08 review → has-errors (round 1 findings R1.1–R1.8)
