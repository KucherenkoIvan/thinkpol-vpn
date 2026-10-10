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

## Log
- 2026-10-10 created in backlog
