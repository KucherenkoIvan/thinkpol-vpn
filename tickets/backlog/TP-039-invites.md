---
id: TP-039
title: "Invites"
milestone: M4
area: features/invites
repo: thinkpol-vpn
size: M
depends_on: [TP-034]
refs: [A2, D7]
owner: ""
branch: ""
---

## Goal
Members join with a single-use, expiring invite.

## Scope
- Invite tokens carrying the space public key and the first node's endpoint and credential.
- Redemption: the device generates its keys and registers through the first node to the controller.
- Rendering as a link and a QR code.

## Acceptance
- [ ] an invite works once, and not after it expires

## Notes
- From TP-003's review: an invite must carry the space id along with the signing key (and the recovery key), so the joining node's first-contact `netmap.Trust` includes `SpaceID` and `netmap.Verify` refuses another space's maps from the start.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): invites carry the space id for first-contact trust
