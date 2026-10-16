---
id: TP-003
title: "Network map envelope v1"
milestone: M0
area: netmap
repo: thinkpol-vpn
size: L
depends_on: [TP-001]
refs: [S1, S6, A5, A11, DESIGN#the-signed-map]
owner: agent-tp-003
branch: tp-003-netmap-envelope
---

## Goal
The format every node trusts: a versioned envelope signed by the space key, with one sealed section per node that only that node can open.

## Scope
- Schema in protobuf in the `proto/` buf module, generated into `proto/gen/` by `make proto` (no `contracts/` tree): header {space id, version, signing public key, recovery public key, hashes of list blobs}, sections [{sealed bytes}], signature. (As built: no recipient key id, see Notes.)
- Section payload v1: the node's own settings and the peers it talks to (node ids, WireGuard public keys, overlay addresses, endpoints, transport credentials). Only what M0 needs, extensible.
- Standard crypto only (`golang.org/x/crypto` and the standard library): ed25519 over the exact serialized bytes (never re-encode to verify); sections sealed as NaCl anonymous sealed boxes (X25519 + XSalsa20-Poly1305, `nacl/box.SealAnonymous`). No custom primitives. (Originally said XChaCha20-Poly1305, which is not the standard sealed box; see Notes.)
- Padding: section count padded to 8/16/32/… with dummy sections indistinguishable from real ones; section sizes padded to buckets so lengths don't reveal what a node does.
- API: `Verify(envelope, spaceKey) → header`, `Open(envelope, nodeKey) → section`, `Accept(current, candidate)` (same space, strictly higher version). (As built after review: `Verify(envelope, Trust)`, `(*Map).Open`, `(*Map).Next`, `Accept`; see Notes.)
- Reserve the recovery record type in the schema (rotation itself is TP-036).

## Out of scope
Gossip (TP-037), building maps from controller state (TP-036).

## Acceptance
- [x] changing any byte of an envelope fails verification — `TestVerifyRejectsChangedBytes` (66 KB envelope: every byte outside the sealed sections with three masks, every byte of one sealed section, a random 1/32 of the rest; 10,884 tampered envelopes, all rejected); `TestVerifyRejectsTruncatedOrExtended` (every truncation; appended fields → `ErrMalformed`, appended recovery records → `ErrUnsupportedFormat`); `TestVerifyRejectsNonCanonicalEnvelope` (swapped fields, padded length varint, padded tag: all decode to the same message and are rejected; 63/65-byte or missing signature; recovery records before the signature); `FuzzVerify` 60 s, 855 k inputs on the final code (776 k and 1.33 M in earlier rounds): nothing but the original envelope verifies, no panics
- [x] a node can't open any section but its own — `TestOpenOnlyOwnSection` (9 nodes, 16 sections: each key opens exactly one sealed box, its own; dummies open for nobody; a stranger gets `ErrNotRecipient`; one's own private key with another node's public key opens nothing); `TestOpenChecksOnlyWellFormedness` (a section of another space, epoch or older version replayed, two sections for one key, bad padding → `ErrMalformed`; newer `min_reader` or unknown own kind → `ErrUnsupportedFormat`; builder-policy violations still open); `TestUnverifiedMapIsUseless` (nil, zero and hand-made `*Map` → `ErrUnverified`)
- [x] real and dummy sections can't be told apart by length or position (test over many generated maps) — `TestPaddingHidesSections`: 60 random maps (0–18 nodes): power-of-two count ≥ 8, equal-length sections, every section starts with a well-formed X25519 key (dummies are real sealed boxes); over 300 maps the real sections' positions pass a χ² test (7 dof, threshold 50, false failure ≈ 1.4e-8 per run). `TestSectionLengthHidesRole`: a PRD-scale space (10 servers, 20 devices) fits 8 KiB sections; one device section outgrowing the bucket moves every section, a ~1 KiB server section included, to 16 KiB. `TestBuildSealsAfresh`: no ephemeral key repeats across builds
- [x] older or equal versions are rejected by `Accept` — `TestAcceptAndNext` (`Accept` and `(*Map).Next`): same version, older, rollback to 1 → `ErrNotNewer`; other space → `ErrOtherSpace`; other recovery key, other key epoch either way → `ErrKeysChanged`; other signing key → `ErrKeysChanged` (`Accept`) / `ErrBadSignature` (`Next`); higher versions up to 2^53 accepted
- [x] pure Go, no cgo — `make lint` passes, incl. the android/arm64 build and `make nocgo` over `internal/netmap`; dependencies `golang.org/x/crypto` (curve25519, nacl/box) and `google.golang.org/protobuf` are pure Go

## Notes
**API** (`internal/netmap`; schema `proto/thinkpol/netmap/v1/netmap.proto`, generated `proto/gen/thinkpol/netmap/v1`, which depguard lets only `internal/netmap` import):
- `Build(signingKey ed25519.PrivateKey, c Contents) ([]byte, error)`; `Contents{SpaceID, KeyEpoch, Version, RecoveryKey, Blobs []BlobRef, Recipients []Recipient{Key NodePublicKey, Section}}`; `ErrInvalidContents` on anything it won't publish.
- `Verify(envelope []byte, trust Trust) (*Map, error)`; `Trust{SpaceID, SigningKey, RecoveryKey}` (space id and recovery key checked when set).
- `(*Map).Next(envelope []byte) (*Map, error)`: verify against `m.Trust()` + `Accept`; the only gossip path.
- `(*Map).Open(key NodePrivateKey) (Section, error)`; `(*Map).Header() Header`, `Trust() Trust`, `Bytes() []byte`, `SectionCount() int`; `Accept(current, candidate *Map) error` (nil current = first map). A `*Map` not made by `Verify`/`Next` is refused with `ErrUnverified`; methods are nil-safe.
- `Header{SpaceID, KeyEpoch, Version, SigningKey, RecoveryKey, Blobs}`; `BlobRef{Kind (BlobGeoIP|BlobGeoSite), SHA256, Size, Name}`.
- `Section{Node NodeSettings, Peers []Peer, Links []Link, Inbound []InboundLink, Routes []Route, Blobs []BlobRef}`; `NodeSettings{ID, Kind, IPv4, IPv6, IPv4Network, IPv6Network, Listeners []Listener{Transport, Address netip.AddrPort, Settings}}`; `Peer{ID, WireGuardKey, Addresses, Paths []Path{FirstHop}}`; `Link{Peer, Endpoints []Endpoint{Transport, Address netip.AddrPort, Credential, Settings}}`; `InboundLink{Peer, PeerKind, Transport, Credential, Settings}`; `Route{Destination, NextHops}`.
- Ids and keys: `SpaceID` (16 bytes), `NodeID` (8), `WireGuardKey`, `NodePublicKey` (`Check()` rejects low-order and non-canonical points) / `NodePrivateKey` (redacted `String`), `NewSpaceID`, `NewNodeID`, `GenerateNodeKey`, hex `Parse*` (`ParseNodePublicKey` runs `Check`).
- Constants: `Format = 1`, `SectionReader = 1`, `MaxEnvelopeSize = 16 MiB`, `MaxVersion = 2^53`. Errors: `ErrMalformed`, `ErrBadSignature`, `ErrUnsupportedFormat`, `ErrNotRecipient`, `ErrOtherSpace`, `ErrKeysChanged`, `ErrNotNewer`, `ErrInvalidContents`, `ErrUnverified`.

**Crypto and encoding:**
- **Standard NaCl sealed box, not XChaCha20.** The standard anonymous sealed box (libsodium `crypto_box_seal`, `nacl/box.SealAnonymous`) is X25519 + XSalsa20-Poly1305; an XChaCha20 variant would be our own construction, and stdlib HPKE needs Go 1.26. Scope corrected.
- **No recipient key id; nodes trial-decrypt.** Stable ids would link a node's sections across versions while dummies change, so two gossiped envelopes would count the real nodes (S6). Two sections opening for one key is `ErrMalformed`.
- **Signatures are Ed25519ctx** (RFC 8032), context `thinkpol-vpn netmap v1`; recovery records use `thinkpol-vpn recovery v1`.
- **Canonical envelope parsed with protowire** without copying: field 1, then field 2 with 64 bytes, minimal tags and lengths, nothing after except recovery records (field 3), which format-1 readers report as `ErrUnsupportedFormat`. The signed body is never re-encoded.
- **Ordering is (key epoch, version).** The epoch changes only by a recovery record (TP-036); until then `Accept` requires equal epochs and keys. `Build` refuses versions above 2^53 (the cap is a builder rule; readers accept any version).
- **Evolution.** `Body` field 1 (format) and field 2 (header, with its layout) are frozen. Additive fields don't bump anything and readers ignore unknown fields (tested for header and section). A field older nodes must not ignore raises the section's `min_reader`; `SectionReader` is this reader's level. Bump `Body.format` only after the release that reads it has rolled out through format-1 maps (DESIGN "Format changes").
- **Recipient keys** must pass `NodePublicKey.Check`: top bit clear, below 2^255−19, and X25519 with a fixed non-zero scalar must succeed (low-order points fail), in `Build` and `ParseNodePublicKey`.
- **`golang.org/x/crypto` pinned at v0.55.0**: v0.56+ needs Go 1.26, above go.mod's floor.

**Padding:** count max(8, next power of two) ≤ 1024; all sections of an envelope pad to one length, max(8 KiB, next power of two above the largest), ≤ 1 MiB, ISO/IEC 7816-4 inside the box; dummies are real sealed boxes to throwaway keys; shuffled with crypto/rand-seeded ChaCha8. `Verify` enforces the shape. `MaxEnvelopeSize` is the binding cap and `Build` checks count × (size + overhead) before sealing. 8 KiB covers the PRD's scale with headroom (at 10 servers and 20 devices, every one of which reaches every other, the fixture's largest section is a device's at ~6.2 KB, entries ~5.3 KB); much larger spaces move to bigger buckets, the residual leak DESIGN records.

**Section model (destination routing):**
- A peer's `Paths` are candidate **first hops** in priority order (failover follows it): an adjacent node, or the peer itself for a direct link. Relays forward by `Routes` (destination → adjacent next hops in priority order; several for a hop group in the middle; next hop = destination delivers). No node holds a whole path.
- Two chains in use at once must end at different exits; that is TP-030's builder check (DESIGN "Routing rules and DNS").
- **Reader vs builder.** `Open` checks only well-formedness: exact lengths, canonical text addresses (empty = absent), no zero ids, no self-references, no repeated keys in keyed lists; own kind 0 is malformed, an unknown own kind unsupported. `Build` adds policy and consistency: IPv4 network inside 100.64.0.0/10; IPv6 a /48 inside fd00::/8; addresses inside them; ≥ 1 address and path per peer, ≥ 1 endpoint per link and next hop per route; first hops and next hops adjacent (a link or an inbound peer); no overlay address used twice; no two inbound links sharing (transport, credential); no repeated listeners, endpoints, paths or addresses; listener and endpoint addresses an IP (no zone, no IPv4-mapped IPv6) with a non-zero port, endpoints not unspecified; transport names `[a-z][a-z0-9-]{0,31}`; credentials 1–1024 bytes; settings ≤ 4 KiB; known kinds; section blobs present in the header with the same kind and size; header blobs unnamed. Policy can tighten without breaking deployed readers.
- `Listener.Settings`, `Endpoint.Settings` and `InboundLink.Settings` are transport-owned bytes (camouflage target, certificate pin, SNI, ws path; on inbound links, how the listener side shapes and configures what it sends, incl. TP-027's per-link shaping). `InboundLink.Credential` is the transport's verifier: a hash or public key where the transport allows (S1), the shared secret itself for a symmetric transport (from TP-005's review).
- **Addresses are IP literals** (from TP-005's review): `Listener.Address` and `Endpoint.Address` are `netip.AddrPort`, and readers accept only canonical `ip:port` text (no host names, no empty host, no zone), so a host name can't reach a node through its map and nodes never ask DNS at dial time; the controller resolves names. A listener binds every address of a family with the unspecified IP (`0.0.0.0:4500`, `[::]:4500`). `InboundLink.PeerKind` lets an ingress-off node refuse devices (TP-013).
- Blobs: the header lists every blob unnamed (relays' availability set); sections name the ones their node uses. Public list hashes are visible to all nodes holding the envelope (accepted, DESIGN "Lists").

**Tooling:**
- Flake check (S2): `go test -count=200 -timeout 90m ./internal/netmap/` passed on d62493b in 925 s. Without `-timeout` it hits go test's default 10-minute limit (one run of the package takes ~5 s), which is not a failure of any test.
- depguard `netmap-schema-only-in-netmap`: checked once with a throwaway import in `internal/agent` — `import '…/proto/gen/thinkpol/netmap/v1' is not allowed from list 'netmap-schema-only-in-netmap'`; `internal/netmap` passes.
- `make lint` runs `make proto-check`: `buf lint`, regenerate into a temp dir and diff against `proto/gen` (checked once: an edited generated file fails), and `buf breaking` with category WIRE against `rewrite` (`BUF_BREAKING_AGAINST`), skipped while `rewrite` has no `.proto` files. Checked once against this branch's first schema commit: it reports the field renumbering as breaking. buf resolves the ref in the shared git dir, so use a branch name or sha, not `HEAD`. `proto/buf.yaml` breaking category changed from FILE to WIRE.

**For downstream tickets:**
- TP-004: signing/recovery keys `ed25519.GenerateKey`; node keys `GenerateNodeKey`; `inspect` = `Verify(env, Trust{SigningKey: …})` + `Header()` + `Open`.
- TP-006: candidate first hops from `Peer.Paths`, forwarding table from `Section.Routes`; node ids are 8 bytes.
- TP-010: per-space credential tables from `Section.Inbound` (with `PeerKind`); listeners from `NodeSettings.Listeners`.
- TP-013 and any new field: schema field, Go field, both conversions, a `validate` rule (and `wellFormed` only if readers must reject it), and the test fixture; raise `min_reader` if older nodes must not ignore it.
- TP-016/TP-017: `BlobRef{Kind, SHA256, Size, Name}`; header = availability set.
- TP-036: see its Notes (key epoch, recovery records in envelope field 3, hooks in `Next`/`Accept`).
- TP-037: store and forward `Map.Bytes()`; take maps with `(*Map).Next`; bootstrap with `Verify(env, trustFromInvite)`.
- TP-040: HostedSpace shape and shared-node listener rules are in its Notes.
- The merge commit of `rewrite` into this branch (d2d7ea4) carries git's default message without the co-author trailer; no force-push to fix it.

## Review findings
Two reviewers (security, architecture); decisions by the orchestrator.

Architecture:
- [x] D1. Destination routing: `relay_to` becomes `repeated Route routes` {destination node id, next hops (adjacent; several for a hop group in the middle)}; `Peer.Paths` become candidate first hops (adjacent nodes, or the peer itself for direct). DESIGN data-plane text, TP-006 (relay header {destination, hop limit} + forwarding table) and TP-030 updated
- [x] D2. Chains active at the same time end at different exits; DESIGN's rule example uses a second exit and explains why; TP-030 acceptance fixed; path order documented as priority (failover)
- [x] D3. `Open` runs only `wellFormed()` (lengths, canonical encodings, no zero ids, no self-references, duplicates); builder policy (overlay ranges, ≥1 path, consistency) only in Build's `validate()`; unknown own NodeKind → `ErrUnsupportedFormat`
- [x] D4. Per-section `min_reader` + `SectionReader` const; header layout frozen across formats; DESIGN: bump `Body.format` only after the release that reads it has rolled out through a format-1 map
- [x] D5. `Trust{SpaceID, SigningKey, RecoveryKey}`; `Verify(envelope, Trust)` (checks the space id when set); `(*Map).Trust()`; `(*Map).Next(envelope)` as the only gossip path; `(*Map).Open(key)`; unexported verified flag checked by Open/Next/Accept; nil-safe
- [x] D6. Header `key_epoch`; maps ordered by (key_epoch, version); `Accept` requires an equal epoch until TP-036; Build rejects versions > 2^53; note for TP-036
- [x] D7. Envelope field 3 defined as `repeated SignedRecoveryRecord recovery_records`; format-1 readers return `ErrUnsupportedFormat` when present
- [x] D8. Canonical outer check by parsing with protowire (minimal varints, tag 1 then tag 2, 64-byte signature, nothing after) without re-marshalling; Build checks count × (size + overhead) against `MaxEnvelopeSize` before sealing
- [x] D9. Section size floor 8 KiB; DESIGN records the residual leak (very large spaces move to bigger buckets); `TestSectionLengthHidesRole` crosses a bucket and shows servers' sections grow with it
- [x] D10. `Listener.settings`, `Endpoint.settings` (transport-owned bytes); `InboundLink.peer_kind`; `InboundLink.credential` documented as a verifier where the transport allows; `BlobRef` gains a kind (and name); header blobs = availability set, sections reference the blobs the node uses; accepted leak documented; TP-040 Notes get the HostedSpace shape and listener/inbound rules for shared nodes

Security:
- [x] S1. Low-order and non-canonical X25519 public keys rejected in Build and `ParseNodePublicKey` (top bit, < p, X25519 with a fixed scalar must not fail); tests with u = 0, 1, p−1, the other known low-order points and a top-bit-set key
- [x] S2. `TestOpenRejectsBadSections` flake fixed (drop every section that opens for the key before laying crafted ones); netmap tests pass with `-count=200`

Also:
- [x] A1. depguard: only `internal/netmap` imports `proto/gen/thinkpol/netmap`
- [x] A2. `make lint` runs `buf lint`, a stale-generated-code check, and `buf breaking` (category WIRE) against `rewrite`, skipped while `rewrite` has no schema
- [x] A3. Builder consistency: duplicate overlay addresses across peers; inbound links sharing (transport, credential); paths whose first hop isn't adjacent; duplicate listeners, endpoints, paths, addresses; listener host an IP literal or empty
- [x] A4. Tests: readers ignore unknown header and section fields; fixture covers direct paths, multi-hop route tables, multi-endpoint links, a device listener
- [x] A5. Nits: "overlay addresses" not "allowed IPs"; ULA fd00::/8 and /48 in builder policy; `Contents.Sections` → `Recipients`; `toID` → `toArray`; comment on the cap interplay; χ² flake-rate comment; `SectionCount` comment; reject `BlobRef` size 0

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-003, branch: tp-003-netmap-envelope
- 2026-10-10 docs: Scope corrected to the standard NaCl sealed box (XSalsa20-Poly1305) and to sections without a recipient key id; DESIGN.md "The signed map" now names the header keys, the absent recipient id and equal-length shuffled sections
- 2026-10-10 in-progress → review — all acceptance checked; `make lint` and `make test` pass
- 2026-10-10 review → has-errors — 10 architecture, 2 security and 5 further findings from review
- 2026-10-10 has-errors → in-progress — owner: agent-tp-003, branch: tp-003-netmap-envelope
- 2026-10-10 TP-005 review additions: `InboundLink.settings` (transport-owned, per-link shaping), credential documented as the transport's verifier (the secret for symmetric transports), listener and endpoint addresses are IP literals (`netip.AddrPort`, enforced by readers and Build); DESIGN "The signed map" says so
- 2026-10-10 in-progress → review — every review finding checked; `make lint`, `make test`, `go test -count=200` on netmap and a 60 s fuzz run pass
- 2026-10-10 delta review fixes: Verify copies the envelope once and reads only the copy (L1); Build's pre-sealing size check uses the exact section framing as a lower bound, and its test proves it fires before sealing (N1); notes for TP-006, TP-008 and TP-039
- 2026-10-10 review → done — merged into rewrite
