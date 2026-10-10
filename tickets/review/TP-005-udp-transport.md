---
id: TP-005
title: "Transport port and udp transport"
milestone: M0
area: dataplane/transport
repo: thinkpol-vpn
size: M
depends_on: [TP-001]
refs: [C1, C3, C6, DESIGN#transports]
owner: "agent-tp-005"
branch: "tp-005-udp-transport"
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
- [x] `udp` passes the conformance suite: `TestConformance` on IPv4 and IPv6 loopback, and `TestConformanceBehindSharedListener` (a worker's Listener fed by a supervisor's `Router`, as TP-010 will run it). That is 20 cases each, including Replay through a tap. The memory adapter passes it under both `Datagram` and `Stream` semantics (Replay skipped: no wire). Green with `go test -race -count=5` on the transport packages.
- [x] a capture of `udp` traffic carrying WireGuard shows no WireGuard message headers: `TestCaptureShowsNoWireGuard` runs two real wireguard-go devices over a udp link through a capturing tap and pings both ways. Output: "captured 4 datagrams carrying 4 WireGuard messages (by type: map[1:1 2:1 4:2]); none recognisable". No datagram matches the WireGuard DPI signature (type, zero reserved bytes, size for the type), and no message's first 16 bytes appear anywhere in the capture. The test also checks that the same classifier flags the raw messages.
- [x] the port is documented in the package doc: `internal/dataplane/transport/doc.go` (the contract), `udp/doc.go` (the design and its limits), and `transporttest` and `memory` package docs.

## Notes
- **Port** (`internal/dataplane/transport`, contract in `doc.go`):
  - `Link`: `ReadPacket`, `WritePacket` (may block), `Close` (unblocks both), `LocalAddr`, `RemoteAddr`. Whole packets of 1 to 8192 bytes. Errors matching `net.ErrClosed` are final (cause `ErrRevoked`, `ErrSuperseded` or an adapter's fatal error, via `ClosedError`); any other error loses one packet.
  - `Dialer.Dial(ctx, endpoint, DialConfig{Credential, Settings, Shaping})`. Endpoints are IP literals.
  - `Listener.Accept(ctx) (Link, Identity, error)`, `Addr`, `Close`. One link per credential: a redial either supersedes (streams) or carries on (datagrams). Revocation closes; a settings change keeps the link. `Accept` may return an already-closed link.
  - `Identity{Space SpaceID [16]byte, Node NodeID [8]byte}`.
  - `PeerLink{Peer, Verifier, Settings, Shaping}`; `Peers.Snapshot()` with `PeerTable`; `PeerError`.
  - `Transport{Name, Dialer, Listen(ctx, ListenConfig{Address, Settings, Peers, Camouflage}), CheckEndpoint, CheckInbound, Overhead(Shaping)}` and an explicit `Registry`.
  - Shared-listener seams: `Router{RouteDatagram, RouteStream}`, `Routable{Transport; Router(peers)}`, `HandoffListener{Listener; ServeStream(conn, consumed)}`.
  - `Camouflage{Datagram, Stream}` with `Drop`; `Shaping` is a placeholder for TP-027.
  - Each direction of a node pair is its own link with its own secret.
- **udp rationale:**
  - **Why stateless:** WireGuard inside already gives confidentiality, integrity, replay protection and roaming. udp only hides WireGuard's headers (C1), authenticates the credential for the shared listener, and drops junk cheaply.
  - **Wire format:** `conn id | random 24-byte nonce | XChaCha20-Poly1305(sender | sent time | counter | packet)`, with one key per credential and direction. Nonce reuse is impossible by construction. The conn id is HKDF of secret, direction and hour; receivers accept adjacent hours.
  - **Freshness:** a datagram sealed more than ±5 minutes from the receiver's clock is dropped and counted as a stale timestamp, which is the clock requirement.
  - **Ordered senders:** a sender carries its creation time. An unknown sender older than the current one is dropped unless the current one has been silent for 30 s. Only the current sender's newest counter moves the reply address.
  - **Guarantee:** captures older than five minutes are dead. While a dialer is active, no replay delivers twice or moves its link.
  - **Residual:** after a listener restart, replays of the last five minutes open a link and deliver once more (WireGuard drops them). An on-path attacker can race a held datagram ahead of the original, as with WireGuard roaming.
  - Overhead is 72 bytes per packet.
- **History:**
  1. AES-GCM sessions; the pre-review found nonce reuse.
  2. Stateless XChaCha with a per-sender LRU; the formal review found the LRU defeatable and that it controlled the reply address.
  3. The current design, with the orchestrator's decisions implemented as stated.
- **Ownership of conversions:**
  - Settings are protobuf in `proto/thinkpol/transport/v1/`: `UdpListenSettings`, `UdpDialSettings` and `UdpInboundSettings`, all empty for now.
  - The map → port conversion belongs to the data-plane engine (`internal/dataplane`), using `CheckEndpoint`/`CheckInbound` and the `Registry`.
  - Both points are recorded in DESIGN.md. TP-003 has added transport-owned settings and IP-literal endpoints to the map, and its id sizes match the port's.
- **Decisions beyond the findings:**
  - `udp.Options.Now` is an injectable clock, so tests can skew it.
  - Receivers expose `Counters()` (on `Listener`, `Router` and dial links) and `Rejected()`.
  - `transporttest.Harness.Credentials` is optional, for asymmetric transports later.
  - The memory `Network` implements `Transport`.
  - Dependencies: `google.golang.org/protobuf` and `golang.org/x/crypto` are direct. `golang.zx2c4.com/wireguard` is required by tests only.
- **For TP-006:** test the path layer on `memory.NewNetwork(memory.Datagram)` and on `memory.NewNetwork(memory.Stream)`. Links don't report liveness, so detect dead paths and redial in the path layer. Socket marks go in `udp.New(udp.Options{Control})`. Budget `Transport.Overhead` into the MTU.
- **For TP-010:** see its Notes. In short: `Router.RouteDatagram`, then forward untouched to the worker running `udp.Transport.ListenOn(pc, …)`; stamp the Space from the source map; charge fair share after the worker accepts. `udp/router_test.go` is a working sketch.
- **For TP-027:** add fields to `Shaping`. `Overhead(Shaping)` must account for them, and adapters refuse settings they can't honour. udp has no padding field yet; its wire format can still change freely.
- **For TP-028:** see its Notes. Use a ClientHello token, `RouteStream`, `HandoffListener`, and the tls settings proto.
- Tests use in-process loopback sockets only; nothing needs root or the lab.

## Review findings
Formal review (two reviewers), orchestrator decisions to implement as stated.

Blocker:
- [x] B1 Replay filter defeatable (8-slot LRU cycling, restart/reindex wipes windows, withheld newest datagram) and it controls the reply address. Fix: (a) sealed coarse timestamp, ±5 min of receiver clock, else dropped and counted as "stale timestamp"; clock requirement documented; (b) ordered senders: sender id carries creation time; an unknown sender older than the newest known is dropped unless the newest has been silent > 30 s; only the newest sender moves the reply address, only on its newest counter; (c) tests: restart then replay (no link, no address move), withheld newest datagram older than the window, 9-sender cycle (RemoteAddr never changes, Accept yields nothing), skewed clock rejected; udp/doc.go and Notes state the real guarantee and the residual.

Should-fix:
- [x] 1 Conn id rotates hourly (HKDF with epoch = floor(t/1h)); listener and demux accept current and adjacent epochs; documented.
- [x] 2 Demux verifies tag and timestamp, then routes; "without decrypting" wording fixed in doc and DESIGN.md; TP-010 note: fair-share charged after the worker accepts; duplicate conn ids drop both and are reported; supervisor stamps Space from the source map.
- [x] 3 Typed ids: `SpaceID [16]byte`, `NodeID [8]byte`, `Identity{Space, Node}` with String(); no netmap import; tests use random ids.
- [x] 4 Split configs: `DialConfig{Credential, Settings, Shaping}`, `PeerLink{Peer, Verifier, Settings, Shaping}`; min-length validation in the adapter.
- [x] 5 `Transport` interface {Name, Dialer, Listen(ctx, ListenConfig{Address, Settings, Peers, Camouflage}), CheckEndpoint, CheckInbound, Overhead(Shaping)} and an explicit `Registry`; socket Control as an adapter option (`udp.New(udp.Options{Control})`).
- [x] 6 Conversion ownership in DESIGN.md and Notes: per-transport settings are protobuf in `proto/thinkpol/transport/v1/` (only what udp needs); netmap → transport conversion lives in `internal/dataplane`; endpoints in the map are IP literals.
- [x] 7 DESIGN decision for tls + shared listener (auth token in the ClientHello, supervisor peeks without terminating, fd + consumed bytes to the worker, otherwise whole connection proxied to camouflage); written into DESIGN.md and TP-010/TP-028/TP-052 Notes; port seams `Router` and `HandoffListener`; udp implements the datagram side.
- [x] 8 Link contract: WritePacket may block; Close unblocks reads and writes; net.ErrClosed final; other errors lose one packet; unrecoverable adapters close themselves with ClosedError(cause); conformance case WriteUnblocksOnClose.
- [x] 9 Config changes with the same credential apply to live links (swap entry, keep windows).
- [x] 10 indexPeers returns what it skipped; listener reports it; CheckInbound used by the conversion layer.
- [x] 11 memory adapter gets Semantics {Stream, Datagram}; doc says which; TP-006 note: test in both.
- [x] 12 Suite: Listen returns `Endpoint{Address, Settings}`; DialConfig built from it; DialContext-deadline case.

Nits:
- [x] backoff on persistent read errors; rejectAfterMessages path removed or fixed; ConnID unexported; camouflage doc (datagram-only camouflage closes streams); port doc forbids one secret for both directions of a link pair and says Accept may return an already-revoked link.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-005, branch: tp-005-udp-transport
- 2026-10-10 reworked udp crypto to a stateless design after the pre-review findings (nonce reuse, epoch rollback); suite extended
- 2026-10-10 in-progress → review
- 2026-10-10 review → has-errors — formal review: 1 blocker, 12 should-fix, nits (see Review findings)
- 2026-10-10 has-errors → in-progress — owner: agent-tp-005, picking up the review findings
- 2026-10-10 merged origin/rewrite (go-kernel v0.18.0); review findings fixed
- 2026-10-10 in-progress → review
