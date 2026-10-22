---
id: TP-036
title: "Publishing, recovery key and backups"
milestone: M4
area: features/publishing
repo: thinkpol-vpn
size: L
depends_on: [TP-035, TP-003]
refs: [A5, A11, S6]
owner: ""
branch: ""
---

## Goal
Every change becomes a new signed map, each node gets only its part, and a lost controller is recoverable.

## Scope
- Projector: build each node's need-to-know section (docs/design/control-plane.md "The signed map": what entries, exits and devices get), seal, pad, sign, bump the version.
- Recovery key: created with the space and shown once as a phrase and QR code, never stored on the controller.
- Signing-key rotation record signed by the recovery key; nodes accept it.
- Controller database backups encrypted to the recovery key; documented restore procedure.

## Acceptance
- [ ] after a simulated controller loss, a new controller restores from backup and rotates the signing key; nodes follow

## Notes
- From TP-003: the header has a `key_epoch` (0 for the space's first signing key) and maps are ordered by (key epoch, version), so a stolen signing key can't freeze the space at a huge version; `netmap.Build` caps versions at 2^53. `RecoveryRecord {space_id, key_epoch, signing_public_key}` and `SignedRecoveryRecord` are in the schema (Ed25519ctx, context `thinkpol-vpn recovery v1`); `Envelope.recovery_records` (field 3) carries them, and format-1 readers report such envelopes as `ErrUnsupportedFormat`. Rotation hooks into `(*netmap.Map).Next` and `netmap.Accept`, which today return `ErrKeysChanged` for any epoch or key change.
- **From TP-017:** some node must hold every published blob: the controller's node (every node's WireGuard peer) seeds its own `blobs/<hex sha256>` in its state directory, and provisioning (TP-038) may seed servers. Header refs unnamed, section refs named (`netmap.BlobRef{Kind, SHA256, Size, Name}`); keep the header's blobs within `blobs.ServerMaxHeldSize` (16 MiB: servers hold them all; `devmap` enforces it); name in a device's section every list its rules use.
- **Downgrade (independent design review, 2026-10-13; TP-062):** a recovery record for epoch N is rejected when the node's current epoch exceeds N, so an old record can't roll the signing key back. Add a test.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): key epoch and recovery record notes
- 2026-10-12 docs (TP-017): notes from blob distribution
- 2026-10-13 docs (TP-062): note: recovery record for epoch N rejected when the current epoch exceeds N
