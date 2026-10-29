---
id: TP-049
title: "Tray app"
milestone: M5
area: cmd/thinkpol-tray
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

## Notes
- 2026-10-29 from the TP-094 reviews (local-API access by group membership): the service should rate-limit its local-API refusal log lines; the tray should back off after a `permission_denied`; on its first run right after the user was added to the group, the tray should wait about 10 s before reporting a refusal; and the tray should tell `service_down` apart from `not_running`.

## Log
- 2026-10-10 created in backlog
- 2026-10-15 docs (backlog grooming): depends on TP-048 for kill-switch control
- 2026-10-15 docs (backlog grooming, review fixes): removed redundant split note
- 2026-10-15 docs: depends on TP-086 (frontend stack revisit)
- 2026-10-29 docs: notes from the TP-094 reviews
