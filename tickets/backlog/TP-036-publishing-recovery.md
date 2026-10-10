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
- Projector: build each node's need-to-know section (DESIGN: what entries, exits and devices get), seal, pad, sign, bump the version.
- Recovery key: created with the space and shown once as a phrase and QR code, never stored on the controller.
- Signing-key rotation record signed by the recovery key; nodes accept it.
- Controller database backups encrypted to the recovery key; documented restore procedure.

## Acceptance
- [ ] after a simulated controller loss, a new controller restores from backup and rotates the signing key; nodes follow

## Notes
- From TP-003: the header has a `key_epoch` (0 for the space's first signing key) and maps are ordered by (key epoch, version), so a stolen signing key can't freeze the space at a huge version; `netmap.Build` caps versions at 2^53. `RecoveryRecord {space_id, key_epoch, signing_public_key}` and `SignedRecoveryRecord` are in the schema (Ed25519ctx, context `thinkpol-vpn recovery v1`); `Envelope.recovery_records` (field 3) carries them, and format-1 readers report such envelopes as `ErrUnsupportedFormat`. Rotation hooks into `(*netmap.Map).Next` and `netmap.Accept`, which today return `ErrKeysChanged` for any epoch or key change.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): key epoch and recovery record notes
