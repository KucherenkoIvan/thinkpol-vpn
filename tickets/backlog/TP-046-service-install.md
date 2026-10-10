---
id: TP-046
title: "Service install and connect-on-boot"
milestone: M5
area: platform
repo: thinkpol-vpn
size: L
depends_on: [TP-022]
refs: [D2, D5]
needs_human: macos
owner: ""
branch: ""
---

## Goal
The client runs as a proper background service on every desktop OS.

## Scope
- `thinkpol service install | uninstall`: launchd daemon (macOS), systemd unit (Linux), Windows service (with TP-047).
- Connect-on-boot toggle, default off.
- Permissions on the local API socket or pipe.

## Acceptance
- [ ] install, reboot, uninstall on macOS and Linux leave the system clean

## Log
- 2026-10-10 created in backlog
