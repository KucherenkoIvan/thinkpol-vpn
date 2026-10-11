---
id: TP-046
title: "Service install and connect-on-boot"
milestone: M5
area: agent
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

## Notes
- **From TP-022's review (acceptance items when this starts):**
  - Install with `THINKPOL_CONNECT=false` (PRD D5: connect-on-boot defaults off); the toggle sets it.
  - Persist the user's last requested connect state (or tell a boot from a restart), so a crash-restart neither silently drops a connected user (traffic leaks until the kill switch, TP-048) nor undoes an explicit disconnect.
  - Create the `thinkpol` group and add the installing user; run the service as root. Leave `/run/thinkpol-api` to the service (it creates it 0750 root:thinkpol and fixes a leftover of its own); don't use systemd's `RuntimeDirectory=` for it unless it ends up exactly that.

## Log
- 2026-10-10 created in backlog
