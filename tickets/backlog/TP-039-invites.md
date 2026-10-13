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
- Redemption creates a **pending device**, not a member's device: its public keys are registered and it has no section, so it reaches nothing. The admin approves it (panel and CLI), which publishes its section; a pending device that isn't approved within a set time expires. The state is the one a removed device already has: known to the controller, no section in the map.

## Acceptance
- [ ] an invite works once, and not after it expires
- [ ] a redeemed invite yields a pending device with no section; it is not in any map until the admin approves it, and approval publishes its section
- [ ] a pending device that isn't approved in time expires and is gone

## Notes
- From TP-003's review: an invite must carry the space id along with the signing key (and the recovery key), so the joining node's first-contact `netmap.Trust` includes `SpaceID` and `netmap.Verify` refuses another space's maps from the start.
- **Invites are not membership (independent design review, 2026-10-13; TP-062).** Invites travel through chat apps and email, so whoever grabs a live one must not join by it alone. How a pending device learns of its approval, since it has no section and so no entry accepts it yet, is part of this ticket's design (it holds the space key and the first node from the invite).

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): invites carry the space id for first-contact trust
- 2026-10-13 docs (TP-062): redemption creates a pending device; approval publishes its section; pending devices expire
