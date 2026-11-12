---
id: TP-049
title: "Tray app"
milestone: M5
area: cmd/thinkpol-tray
stream: clients
repo: thinkpol-vpn
size: epic
depends_on: [TP-046, TP-048, TP-086]
refs: [D2, D3, D9, D10]
needs_human: decision
owner: ""
branch: ""
---

## Goal
Members use thinkpol from a tray icon, never a terminal.

## Scope (split before starting)
- Framework decision first (e.g. `fyne.io/systray`, Wails, Tauri): a decision for the author before splitting.
- Menu: connect/disconnect, status (chain, entry, health, `owned by <space>`), space switcher, rule presets, kill switch, connect-on-boot.
- Talks to the service over the local API; live status needs streaming (KRN-002).
- The kill switch's off state is unmissable: the icon changes colour while the kill switch is off, and the tray sends a notification or alert when it goes off and again while it stays off (owner, 2026-11-12: there is no captive-portal pause, TP-204 dropped).

## Acceptance
- [ ] while the kill switch is off the tray icon has its own colour, and the tray notifies or alerts when the kill switch goes off and again while it stays off

## Notes
- 2026-10-29 from the TP-094 reviews (local-API access by group membership): the service should rate-limit its local-API refusal log lines; the tray should back off after a `permission_denied`; on its first run right after the user was added to the group, the tray should wait about 10 s before reporting a refusal; and the tray should tell `service_down` apart from `not_running`.
- **TP-139 verdicts (TP-139 owner session, 2026-11-07; docs/design/api-overview.md "Verdicts", docs/design/configuration.md).** Tray toggles (connect-on-boot, kill switch, allow-LAN, rule preset) go through the local API, as device-level settings the service stores (TP-166); the tray needs no root for any of them. It reads `status` in TP-168's JSON convention and acts on codes, not wording.
- Owner, 2026-11-12 (TP-204 dropped): no captive-portal pause. A pause is as easy to forget to end as the kill switch is to forget to turn back on; behind a portal the member turns the kill switch off (or uses allow-LAN where the portal is on a private address), then back on. So the tray makes the off state unmissable: an icon colour while it is off, and a notification or alert when it goes off and while it stays off.

## Log
- 2026-10-10 created in backlog
- 2026-10-15 docs (backlog grooming): depends on TP-048 for kill-switch control
- 2026-10-15 docs (backlog grooming, review fixes): removed redundant split note
- 2026-10-15 docs: depends on TP-086 (frontend stack revisit)
- 2026-10-29 docs: notes from the TP-094 reviews
- 2026-11-07 TP-139 verdicts noted
- 2026-11-12 scope: the kill switch's off state is unmissable (icon colour, notification or alert), with an acceptance box; pause removed from the toggles (owner, 2026-11-12; TP-204 dropped)
