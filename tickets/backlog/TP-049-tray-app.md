---
id: TP-049
title: "Tray app"
milestone: M5
area: cmd/thinkpol-tray
repo: thinkpol-vpn
size: epic
depends_on: [TP-046]
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

## Log
- 2026-10-10 created in backlog
