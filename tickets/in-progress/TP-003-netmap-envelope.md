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
- API: `Verify(envelope, spaceKey) → header`, `Open(envelope, nodeKey) → section`, `Accept(current, candidate)` (same space, strictly higher version).
- Reserve the recovery record type in the schema (rotation itself is TP-036).

## Out of scope
Gossip (TP-037), building maps from controller state (TP-036).

## Acceptance
- [x] changing any byte of an envelope fails verification — `TestVerifyRejectsAnyChangedByte` flips every byte of an 8.8 KB envelope with three masks (0x01, 0x80, 0xff); `TestVerifyRejectsTruncatedOrExtended` (every truncation, five kinds of appended field incl. reserved field 3); `TestVerifyRejectsNonCanonicalEnvelope` (same message, swapped fields or padded varint); `FuzzVerify` ran 60 s, 1.33 M inputs: nothing but the original envelope verifies, no panics
- [x] a node can't open any section but its own — `TestOpenOnlyOwnSection` (9 nodes, 16 sections: every key opens exactly one sealed box, its own; dummies open for nobody; a stranger gets `ErrNotRecipient`; another node's public key with one's own private key opens nothing); `TestOpenRejectsBadSections` (section of another space, an older version replayed, two sections for one key, bad padding, non-canonical or invalid content)
- [x] real and dummy sections can't be told apart by length or position (test over many generated maps) — `TestPaddingHidesSections`: 100 random maps (0–17 nodes) have a power-of-two count ≥ 8, equal-length sections, and every section starts with a well-formed X25519 key (dummies are real sealed boxes); over 400 maps the real sections' positions pass a χ² uniformity test (7 dof, p = 0.0001). `TestSectionLengthHidesRole`: dropping the servers' small sections leaves section and envelope length unchanged. `TestBuildSealsAfresh`: no ephemeral key repeats across builds
- [x] older or equal versions are rejected by `Accept` — `TestAccept`: same version, same map, older, rollback to 1 → `ErrNotNewer`; other space → `ErrOtherSpace`; other signing or recovery key → `ErrKeysChanged`; nil current and higher versions accepted
- [x] pure Go, no cgo — `make lint` passes, incl. the android/arm64 build and `make nocgo` over `internal/netmap`; new dependencies are `golang.org/x/crypto` (curve25519, nacl/box) and `google.golang.org/protobuf`, both pure Go

## Notes
**API** (`internal/netmap`, schema `proto/thinkpol/netmap/v1/netmap.proto`, generated `proto/gen/thinkpol/netmap/v1`, Go package `netmapv1`; only `netmap` should touch the generated types):
- `Build(signingKey ed25519.PrivateKey, Contents) ([]byte, error)` with `Contents{SpaceID, Version, RecoveryKey, Blobs []BlobRef, Sections []Recipient{Key NodePublicKey, Section}}`; validates everything, returns `ErrInvalidContents` on bad input.
- `Verify(envelope []byte, signingKey ed25519.PublicKey) (*Map, error)`; `Map.Header()`, `Map.Bytes()` (the exact bytes to store and gossip, never re-encode), `Map.SectionCount()`.
- `Open(*Map, NodePrivateKey) (Section, error)`; `Accept(current, candidate *Map) error` (nil current accepts).
- Section model: `Section{Node NodeSettings, Peers []Peer, Links []Link, Inbound []InboundLink, RelayTo []NodeID}`; `NodeSettings{ID, Kind (NodeServer|NodeDevice), IPv4, IPv6 netip.Addr, IPv4Network, IPv6Network netip.Prefix, Listeners []Listener{Transport, Address}}`; `Peer{ID, WireGuardKey, Addresses []netip.Addr, Paths []Path{Via []NodeID}}` (empty `Via` = direct link); `Link{Peer, Endpoints []Endpoint{Transport, Address, Credential}}` (outbound, in preference order); `InboundLink{Peer, Transport, Credential}` (who may connect to this node).
- Ids and keys: `SpaceID` (16 random bytes), `NodeID` (8 random bytes, unique per space), `WireGuardKey`, `NodePublicKey`/`NodePrivateKey` (X25519 map key; `String` on the private key is redacted), `NewSpaceID`, `NewNodeID`, `GenerateNodeKey`, `Parse*` (hex).
- Errors: `ErrMalformed`, `ErrBadSignature`, `ErrUnsupportedFormat`, `ErrNotRecipient`, `ErrOtherSpace`, `ErrKeysChanged`, `ErrNotNewer`, `ErrInvalidContents`.

**Decisions beyond the ticket text:**
- **Standard NaCl sealed box, not XChaCha20.** The ticket said "X25519 + XChaCha20-Poly1305 (anonymous sealed box)", but the standard anonymous sealed box (libsodium `crypto_box_seal`, x/crypto `nacl/box.SealAnonymous`) is X25519 + XSalsa20-Poly1305. An XChaCha20 variant would be our own construction (DESIGN rule 4), and HPKE in the standard library needs Go 1.26, above go.mod's 1.25 floor. Same security level; Scope corrected.
- **No recipient key id; nodes trial-decrypt.** A stable key id would link a node's section across versions while dummies are fresh, so anyone comparing two gossiped envelopes could count the real nodes (S6). A per-version hint would be home-made. Trying every section costs at most a few dozen X25519 operations. Every section is tried, and two sections opening for one key is `ErrMalformed`.
- **Signatures are Ed25519ctx** (RFC 8032, stdlib `crypto/ed25519`, which `x/crypto/ed25519` aliases) with context `thinkpol-vpn netmap v1`; recovery records must use `thinkpol-vpn recovery v1`, so neither signature can stand in for the other.
- **Canonical outer envelope.** `Envelope{body, signature}` must re-encode to exactly the input bytes with no unknown fields, so no byte outside the signed body can change either. The signed body is never re-encoded.
- **Format and compatibility.** `Body.format` (field 1 in every version) is read with `protowire` before the body is decoded, so a newer layout is `ErrUnsupportedFormat`, not `ErrMalformed`. Additive fields in the header or sections don't bump it and older nodes ignore them (they are signed). A field an older node must not ignore needs a format bump.
- **Padding.** Section count max(8, next power of two), at most 1024. Every section in an envelope has the same padded plaintext length: max(1 KiB, next power of two above the largest section), at most 1 MiB, ISO/IEC 7816-4 padding inside the box. Dummies are real sealed boxes to throwaway keys, because random bytes would be distinguishable: an X25519 public key never has its top bit set. Sections are shuffled with a ChaCha8 seeded from crypto/rand. `Verify` enforces all of this (power-of-two count, equal lengths, bucket size), so a buggy builder fails loudly instead of leaking. Envelopes are capped at 16 MiB (`MaxEnvelopeSize`). For scale: 3 nodes make an 8.8 KB envelope; 10 servers and 20 devices (each device with 19 peers × 10 paths) make 32 sections of 8 KiB, 264 KB in all.
- **Sections are bound to their envelope.** The plaintext carries space id and map version and `Open` checks them, so a sealed section can't be replayed into another version or space, and `Build` seals everything afresh on every call.
- **`Accept` also requires the same signing and recovery keys** (`ErrKeysChanged`). Signing-key rotation by a recovery record is where TP-036 hooks in.
- **The node map key is its own X25519 key per space**, not the WireGuard key (no cross-protocol key reuse). DESIGN.md "The signed map" now says so.
- **The format checks well-formedness; policy belongs to the builder.** Checked: canonical text addresses and prefixes, exact id and key lengths, IPv4 network inside 100.64.0.0/10, IPv6 network inside fc00::/7, node and peer addresses inside the overlay, at least one path per peer, no self-references, loops or duplicates, transport names `[a-z][a-z0-9-]{0,31}`, `host:port` with an explicit port (listener host may be empty), credentials of 1–1024 bytes. Which node may know what (ingress-off nodes, roles) is TP-013/TP-036's job.
- **`golang.org/x/crypto` is pinned at v0.55.0**: v0.56+ requires Go 1.26 and would bump go.mod past go-kernel's floor. Keep it there on `go get -u`.

**For downstream tickets:**
- TP-004: signing and recovery keys are plain `ed25519.GenerateKey`; node map keys `GenerateNodeKey`; `inspect` is `Verify` + `Header()` + `Open`. Hex `Parse*` helpers exist; private key files are hex of the 32 bytes.
- TP-006: `Peer.Paths` (empty `Via` = direct) and `Section.RelayTo`; node ids are 8 bytes, so the relay header stays short.
- TP-010: per-space credential tables come from `Section.Inbound`; listeners from `NodeSettings.Listeners`.
- TP-013 and later fields: add the proto field, the Go field, both directions in `sectionToProto`/`sectionFromProto`, a `validate` rule, and put it in the test fixture so the round-trip test covers it.
- TP-016/TP-017: `Header.Blobs` are `{SHA256, Size}`.
- TP-036: `SignedRecoveryRecord`/`RecoveryRecord` are defined in the schema and `Envelope` field 3 is reserved for carrying them. Until then, v1 rejects envelopes that carry any (they would be unknown fields).
- TP-037: store and forward `Map.Bytes()` as is; a node runs `Verify` with its trusted key, then `Accept`.

## Review findings
Two reviewers (security, architecture); decisions by the orchestrator.

Architecture:
- [ ] D1. Destination routing: `relay_to` becomes `repeated Route routes` {destination node id, next hops (adjacent; several for a hop group in the middle)}; `Peer.Paths` become candidate first hops (adjacent nodes, or the peer itself for direct). DESIGN data-plane text, TP-006 (relay header {destination, hop limit} + forwarding table) and TP-030 updated
- [ ] D2. Chains active at the same time end at different exits; DESIGN's rule example uses a second exit and explains why; TP-030 acceptance fixed; path order documented as priority (failover)
- [ ] D3. `Open` runs only `wellFormed()` (lengths, canonical encodings, no zero ids, no self-references, duplicates); builder policy (overlay ranges, ≥1 path, consistency) only in Build's `validate()`; unknown own NodeKind → `ErrUnsupportedFormat`
- [ ] D4. Per-section `min_reader` + `SectionReader` const; header layout frozen across formats; DESIGN: bump `Body.format` only after the release that reads it has rolled out through a format-1 map
- [ ] D5. `Trust{SpaceID, SigningKey, RecoveryKey}`; `Verify(envelope, Trust)` (checks the space id when set); `(*Map).Trust()`; `(*Map).Next(envelope)` as the only gossip path; `(*Map).Open(key)`; unexported verified flag checked by Open/Next/Accept; nil-safe
- [ ] D6. Header `key_epoch`; maps ordered by (key_epoch, version); `Accept` requires an equal epoch until TP-036; Build rejects versions > 2^53; note for TP-036
- [ ] D7. Envelope field 3 defined as `repeated SignedRecoveryRecord recovery_records`; format-1 readers return `ErrUnsupportedFormat` when present
- [ ] D8. Canonical outer check by parsing with protowire (minimal varints, tag 1 then tag 2, 64-byte signature, nothing after) without re-marshalling; Build checks count × (size + overhead) against `MaxEnvelopeSize` before sealing
- [ ] D9. Section size floor 8 KiB; DESIGN records the residual leak (very large spaces move to bigger buckets); `TestSectionLengthHidesRole` crosses a bucket and shows servers' sections grow with it
- [ ] D10. `Listener.settings`, `Endpoint.settings` (transport-owned bytes); `InboundLink.peer_kind`; `InboundLink.credential` documented as a verifier where the transport allows; `BlobRef` gains a kind (and name); header blobs = availability set, sections reference the blobs the node uses; accepted leak documented; TP-040 Notes get the HostedSpace shape and listener/inbound rules for shared nodes

Security:
- [ ] S1. Low-order and non-canonical X25519 public keys rejected in Build and `ParseNodePublicKey` (top bit, < p, X25519 with a fixed scalar must not fail); tests with u = 0, 1, p−1, the other known low-order points and a top-bit-set key
- [ ] S2. `TestOpenRejectsBadSections` flake fixed (drop every section that opens for the key before laying crafted ones); netmap tests pass with `-count=200`

Also:
- [ ] A1. depguard: only `internal/netmap` imports `proto/gen/thinkpol/netmap`
- [ ] A2. `make lint` runs `buf lint`, a stale-generated-code check, and `buf breaking` (category WIRE) against `rewrite`, skipped while `rewrite` has no schema
- [ ] A3. Builder consistency: duplicate overlay addresses across peers; inbound links sharing (transport, credential); paths whose first hop isn't adjacent; duplicate listeners, endpoints, paths, addresses; listener host an IP literal or empty
- [ ] A4. Tests: readers ignore unknown header and section fields; fixture covers direct paths, multi-hop route tables, multi-endpoint links, a device listener
- [ ] A5. Nits: "overlay addresses" not "allowed IPs"; ULA fd00::/8 and /48 in builder policy; `Contents.Sections` → `Recipients`; `toID` → `toArray`; comment on the cap interplay; χ² flake-rate comment; `SectionCount` comment; reject `BlobRef` size 0

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-003, branch: tp-003-netmap-envelope
- 2026-10-10 docs: Scope corrected to the standard NaCl sealed box (XSalsa20-Poly1305) and to sections without a recipient key id; DESIGN.md "The signed map" now names the header keys, the absent recipient id and equal-length shuffled sections
- 2026-10-10 in-progress → review — all acceptance checked; `make lint` and `make test` pass
- 2026-10-10 review → has-errors — 10 architecture, 2 security and 5 further findings from review
- 2026-10-10 has-errors → in-progress — owner: agent-tp-003, branch: tp-003-netmap-envelope
