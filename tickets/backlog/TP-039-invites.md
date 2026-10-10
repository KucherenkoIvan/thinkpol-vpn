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

## Log
- 2026-10-10 created in backlog
