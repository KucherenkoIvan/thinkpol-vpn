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
- [x] `udp` passes the conformance suite: `TestConformance` on IPv4 and IPv6 loopback, and `TestConformanceBehindSharedListener` (a worker's Listener fed by a supervisor's `Demux`, as TP-010 will run it); 17 cases each, including Replay through a tap. The in-memory adapter passes it too (Replay skipped: no wire). Also green with `-race` and over 6 repeated runs.
- [x] a capture of `udp` traffic carrying WireGuard shows no WireGuard message headers: `TestCaptureShowsNoWireGuard` runs two real wireguard-go devices over a udp link through a capturing tap and pings both ways. Output: "captured 4 datagrams carrying 4 WireGuard messages (by type: map[1:1 2:1 4:2]); none recognisable". No datagram matches the WireGuard DPI signature (type, zero reserved bytes, size for the type), and no message's first 16 bytes appear anywhere in the capture. The test also checks that the same classifier flags the raw messages.
- [x] the port is documented in the package doc: `internal/dataplane/transport/doc.go` (the contract), `udp/doc.go` (the design and its limits), and `transporttest` and `memory` package docs.

## Notes
- **Port** (`internal/dataplane/transport`):
  - `Link`: `ReadPacket(p) (int, error)`, `WritePacket(p) error`, `Close`, `LocalAddr`, `RemoteAddr`. Whole packets of 1 to `MaxPacketSize` (8192) bytes, best effort, never forged. Once closed, it returns errors matching `net.ErrClosed`, plus `ErrRevoked` or `ErrSuperseded` when the listener closed it.
  - `Dialer.Dial(ctx, endpoint, LinkConfig) (Link, error)`.
  - `Listener`: `Accept(ctx) (Link, Identity, error)`, `Addr`, `Close`, which closes every link it accepted. It keeps one link per credential. The peer table is a `Peers` (`Snapshot() ([]PeerLink, <-chan struct{})`, with `PeerTable` as the simple implementation); links whose credential leaves it close with `ErrRevoked`.
  - `LinkConfig{Credential{Secret ≥32 bytes}, Shaping}`. `Shaping` is an empty placeholder for TP-027.
  - `Camouflage{Datagram(p, from); Stream(conn, consumed)}`, with `Drop` as the default.
- **udp rationale:** the udp layer carries no session state, on purpose. WireGuard inside already gives confidentiality, integrity, replay protection and roaming, so udp only hides WireGuard's headers (C1), authenticates the credential for demux, and drops junk.
  - Each datagram is `conn id | random 24-byte nonce | XChaCha20-Poly1305(sender id | counter | packet)`, under a fixed key per credential and direction (HKDF-SHA256). Nonce reuse is impossible by construction across restarts, redials and table changes.
  - The replay window (per random sender id, last 8 senders) is a cheap pre-filter that a restart resets; WireGuard's replay protection is the guarantee.
  - The link's address moves only on a sender's newest counter. An on-path attacker can still race a captured datagram ahead of the original, as with WireGuard's roaming.
  - Overhead is 64 bytes per packet, before IP and UDP headers.
- **History:** the first version used AES-GCM with per-session keys and counter nonces. An adversarial review proved nonce reuse when a listener restarted, a link closed or the table changed, and epoch rollback by replays. Per the orchestrator, it was replaced by the stateless design above, not patched.
- **Decisions beyond the ticket:**
  - Redial semantics are in the port. A stream transport's listener replaces the old link (`ErrSuperseded`); a datagram transport may carry on the same link and follow the dialer. udp carries on; memory replaces.
  - A dialer's udp link survives a listener restart. The memory adapter closes dialer ends instead, so the layer above redials.
  - `transport/memory` was added for TP-006's in-process tests.
  - Dependencies: `golang.org/x/crypto` (chacha20poly1305) is now direct. `golang.zx2c4.com/wireguard` is required for tests only, and TP-006/TP-008 need it anyway; resolve any `go.mod` merge conflict with `go mod tidy`.
- **For TP-006 (path layer):** use `memory.NewNetwork()` (`Listen`, and `Network` as the `Dialer`) for the three-node test. Links don't report liveness, so dead-path detection and redial are the path layer's job. `udp.Dialer.Control` can set a socket mark so transport sockets bypass the TUN. Budget the MTU for `udp.Overhead`.
- **For TP-010 (shared listener):**
  - The supervisor routes each datagram with `udp.NewDemux(peers).Route(d) → (Identity, ok)`. This is a connection id lookup followed by tag verification, so forgeries never reach a worker; `ok == false` goes to the camouflage.
  - It forwards the datagram untouched to the worker of `Identity.Space`. The worker runs `udp.NewListener(pc, itsSpacePeers, camo)` over a `net.PacketConn` that reads forwarded datagrams and writes replies out through the public socket.
  - `TestConformanceBehindSharedListener` and `TestWorkersGetOnlyTheirOwnLinks` in `udp/demux_test.go` are a working sketch of this.
  - A `Peers` merged across spaces works, because `Identity` carries the space.
- **For TP-027 (shaping):**
  - Add fields to `Shaping`. Adapters must refuse settings they can't honour.
  - udp's plaintext has no padding or frame-type field yet. Since nothing is deployed, change the wire format freely, and extend `transporttest` with shaping cases.
- **For TP-028 (tls):**
  - Implement `Harness.Listen` with restart support (same endpoint), and `Interpose` if you want the Replay case (a TCP replayer).
  - Use `Camouflage.Stream(conn, consumed)` for the probe fallback.
  - Supersede older links with `ErrSuperseded`.
  - The certificate pin can go into `Credential` as a new field, or into the endpoint.
  - Handing an fd over after a TLS handshake can't carry the TLS state, so TP-010/TP-028 will need either the supervisor to keep proxying, or the worker to terminate TLS.
- **Tests stay on the host:** loopback sockets in-process only. Nothing needs root or the lab.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-005, branch: tp-005-udp-transport
- 2026-10-10 reworked udp crypto to a stateless design after the pre-review findings (nonce reuse, epoch rollback); suite extended
- 2026-10-10 in-progress → review
