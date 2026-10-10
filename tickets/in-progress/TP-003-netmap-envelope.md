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
- [ ] changing any byte of an envelope fails verification
- [ ] a node can't open any section but its own
- [ ] real and dummy sections can't be told apart by length or position (test over many generated maps)
- [ ] older or equal versions are rejected by `Accept`
- [ ] pure Go, no cgo

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-003, branch: tp-003-netmap-envelope
- 2026-10-10 docs: Scope corrected to the standard NaCl sealed box (XSalsa20-Poly1305) and to sections without a recipient key id; DESIGN.md "The signed map" now names the header keys, the absent recipient id and equal-length shuffled sections
