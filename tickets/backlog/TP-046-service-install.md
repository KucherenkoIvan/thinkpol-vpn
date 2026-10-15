---
id: TP-046
title: "Service install and connect-on-boot"
milestone: M2
area: agent
repo: thinkpol-vpn
size: L
depends_on: [TP-022, TP-075]
refs: [D2, D5]
needs_human: macos
owner: ""
branch: ""
---

## Goal
The client runs as a proper background service on macOS and Linux (Windows: TP-047).

## Scope
- `thinkpol service install | uninstall`: launchd daemon (macOS), systemd unit (Linux). Windows service: TP-047.
- Connect-on-boot toggle, default off.
- Permissions on the local API socket or pipe.

## Acceptance
- [ ] install, reboot, uninstall on macOS and Linux leave the system clean
- [ ] connect-on-boot is off by default after install (PRD D5); the toggle enables it
- [ ] after a simulated crash the service restarts the agent and restores the persisted connect state; fail-closed during the gap is verified in TP-048

## Notes
- **From TP-022's review (acceptance items when this starts):**
  - Install with `THINKPOL_CONNECT=false` (PRD D5: connect-on-boot defaults off); the toggle sets it.
  - Persist the user's last requested connect state (or tell a boot from a restart), so a crash-restart neither silently drops a connected user (traffic leaks until the kill switch, TP-048) nor undoes an explicit disconnect.
  - Create the `thinkpol` group and add the installing user; run the service as root. Leave `/run/thinkpol-api` to the service (it creates it 0750 root:thinkpol and fixes a leftover of its own); don't use systemd's `RuntimeDirectory=` for it unless it ends up exactly that.
- **Crash posture (independent design review, 2026-10-13; TP-062).** The service must restart after a crash and the device must stay fail-closed until it does (default for the "everything" and "all but domestic" presets, opt-out; the guard is TP-048's). The persisted connect state above tells a crash from a deliberate disconnect, which still follows the kill-switch toggle (PRD D4). macOS must meet this too (launchd's restart and the pf guard).
- **Host lock needs a stable inode (TP-060).** The agent lock `/run/thinkpol/agent.lock` only works while its inode survives. Do NOT use `RuntimeDirectory=thinkpol`: systemd deletes the directory when the unit stops, including when the unit stops because it lost the lock, and a later agent would then lock a fresh inode while the old holder still runs. Create `/run/thinkpol` yourself (the agent does, root 0700), or set `RuntimeDirectoryPreserve=yes`.

## Log
- 2026-10-10 created in backlog
- 2026-10-13 docs (TP-062): crash posture: restart after a crash, fail-closed until then, macOS included
- 2026-10-13 notes: the host lock and systemd's `RuntimeDirectory=` (TP-060)
- 2026-10-15 docs (independent review 2026-10-15): depends on TP-075 (agent refactor before service install)
- 2026-10-15 docs (backlog grooming): milestone M2; Windows service moved to TP-047; connect-on-boot and crash acceptance added
- 2026-10-15 docs (backlog grooming, review fixes): Goal scoped to macOS/Linux; crash acceptance decoupled from TP-048 fail-closed check
