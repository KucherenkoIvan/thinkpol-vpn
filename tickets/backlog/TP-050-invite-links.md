---
id: TP-050
title: "Invite links"
milestone: M5
area: cmd/thinkpol-tray
repo: thinkpol-vpn
size: M
depends_on: [TP-039, TP-049]
refs: [D7]
owner: ""
branch: ""
---

## Goal
Opening an invite link joins the space from the tray app.

## Scope
- `thinkpol://join/<token>` handler registered on each OS.
- Tray flow: open link → confirm the space → join → connected.
- The admin panel shows invites as link and QR code (QR scanning comes with Android).

## Acceptance
- [ ] clicking an invite link on a fresh machine with the app installed ends connected

## Notes
- Acceptance says the invite ends connected; PRD D7 and TP-039 say a redeemed device stays pending until approved. Settle in the UX design round (ORCHESTRATION, Decisions 2026-10-15).

## Log
- 2026-10-10 created in backlog
- 2026-10-15 docs (backlog grooming): Notes on invite connected vs pending (UX design round)
