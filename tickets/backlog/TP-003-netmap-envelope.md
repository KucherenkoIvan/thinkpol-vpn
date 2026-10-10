---
id: TP-003
title: "Network map envelope v1"
milestone: M0
area: netmap
repo: thinkpol-vpn
size: L
depends_on: [TP-001]
refs: [S1, S6, A5, A11, DESIGN#the-signed-map]
owner: ""
branch: ""
---

## Goal
The format every node trusts: a versioned envelope signed by the space key, with one sealed section per node that only that node can open.

## Scope
- Schema in protobuf in the `proto/` buf module, generated into `proto/gen/` by `make proto` (no `contracts/` tree): header {space id, version, signing public key, recovery public key, hashes of list blobs}, sections [{recipient key id, sealed bytes}], signature.
- Section payload v1: the node's own settings and the peers it talks to (node ids, WireGuard public keys, overlay addresses, endpoints, transport credentials). Only what M0 needs, extensible.
- Crypto from `golang.org/x/crypto` only: ed25519 over the exact serialized bytes (never re-encode to verify); sections sealed with X25519 + XChaCha20-Poly1305 (anonymous sealed box). No custom primitives.
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
