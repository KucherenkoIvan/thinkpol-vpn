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
owner: "agent-tp-046"
branch: "tp-046-service-install"
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
- [ ] macOS: an agent the launchd daemon starts at boot before the system has loaded `/etc/pf.conf` doesn't run without its IPv6 guard: it waits for the `com.apple/*` hook (or retries until it is there) and stays fail-closed meanwhile; a boot test on a device shows it
- [ ] after a simulated crash the service restarts the agent and restores the persisted connect state; fail-closed during the gap is verified in TP-048

## Notes
- **From TP-022's review (acceptance items when this starts):**
  - Install with `THINKPOL_CONNECT=false` (PRD D5: connect-on-boot defaults off); the toggle sets it.
  - Persist the user's last requested connect state (or tell a boot from a restart), so a crash-restart neither silently drops a connected user (traffic leaks until the kill switch, TP-048) nor undoes an explicit disconnect.
  - Create the `thinkpol` group and add the installing user; run the service as root. Leave `/run/thinkpol-api` to the service (it creates it 0750 root:thinkpol and fixes a leftover of its own); don't use systemd's `RuntimeDirectory=` for it unless it ends up exactly that.
- **Crash posture (independent design review, 2026-10-13; TP-062).** The service must restart after a crash and the device must stay fail-closed until it does (default for the "everything" and "all but domestic" presets, opt-out; the guard is TP-048's). The persisted connect state above tells a crash from a deliberate disconnect, which still follows the kill-switch toggle (PRD D4). macOS must meet this too (launchd's restart and the pf guard).
- **Host lock needs a stable inode (TP-060).** The agent lock `/run/thinkpol/agent.lock` only works while its inode survives. Do NOT use `RuntimeDirectory=thinkpol`: systemd deletes the directory when the unit stops, including when the unit stops because it lost the lock, and a later agent would then lock a fresh inode while the old holder still runs. Create `/run/thinkpol` yourself (the agent does, root 0700), or set `RuntimeDirectoryPreserve=yes`.
- **pf boot race (DESIGN, "The leak guard on macOS").** The guard's anchor hangs under Apple's `anchor "com.apple/*"` hook from `/etc/pf.conf`. An agent started at boot before the system loads that file finds no hook; DESIGN hands this race to this ticket.

## Log
- 2026-10-10 created in backlog
- 2026-10-13 docs (TP-062): crash posture: restart after a crash, fail-closed until then, macOS included
- 2026-10-13 notes: the host lock and systemd's `RuntimeDirectory=` (TP-060)
- 2026-10-15 docs (independent review 2026-10-15): depends on TP-075 (agent refactor before service install)
- 2026-10-15 docs (backlog grooming): milestone M2; Windows service moved to TP-047; connect-on-boot and crash acceptance added
- 2026-10-15 docs (backlog grooming, review fixes): Goal scoped to macOS/Linux; crash acceptance decoupled from TP-048 fail-closed check
- 2026-10-22 docs (TP-077 residual-risks research): the macOS pf boot race, which DESIGN hands to this ticket, added to Notes and Acceptance
- 2026-10-22 backlog → in-progress — owner: agent-tp-046, branch: tp-046-service-install
- 2026-10-22 plan, one slice at a time, each shown working before the next: (1) the persisted connect request, stamped with the boot, and its tests; (2) the systemd unit and `service install`/`uninstall` on Linux, proven in a lab node running systemd (install, crash-restart, reboot, uninstall); (3) the launchd plist and its install/uninstall as files and commands, tested as files (`plutil -lint` on a copy) and with a fake launchctl; (4) the pf boot race: a missing `com.apple/*` hook early in a boot is retried, not terminal (fake pfctl tests); (5) the connect-on-boot toggle, docs, RESIDUAL-RISKS rows, the device checklist
- 2026-10-22 slice 1, the persisted connect request: each local API Connect/Disconnect is recorded before it is acted on (`/run/thinkpol/connect`, `/private/var/db/thinkpol/connect`, stamped with the boot session; trusteddir.BootSession now reads the boot id on Linux), and a start in the same boot follows it over `-connect`; a boot, or a node without a local API, follows `-connect`. Tests: TestARestartInTheSameBootKeepsTheLastConnectRequest, TestARequestWhileRemovedIsRecorded, TestTheConnectRecordKeepsTheLastRequestOfItsBoot, TestAConnectRecordThatCantBeReadIsAnError, TestABootIDIsOneField; mutations seen failing: the record ignored at start, the runner not recording, a request while removed not recorded, the no-API guard dropped, another boot's record read, the boot id's one-field check dropped (lab). Lab: agent and trusteddir packages pass in a lab node
- 2026-10-22 slice 1, follow-up: the first start of a boot records its own choice (as configured), so a device connected by connect-on-boot that crashes after the toggle was turned off comes back connected; TestARestartInTheSameBootKeepsTheLastConnectRequest covers it (mutation: the first start not recording, seen failing)
- 2026-10-22 slice 2, the service on Linux: package agent/service (the systemd unit and the launchd plist as definitions, an Installer over a root path and a service manager's tools) and `thinkpol service install|uninstall|connect-on-boot`; the lab runs systemd as an unprivileged node's PID 1 (NodeSpec.Systemd, Node.Restart as a reboot that reseals the node). Lab TestServiceUnderSystemd: install (unit, binary 0755 root, group with alice, connect-on-boot off), alice connects over the group, `systemctl kill -s KILL` twice restarts the agent connected then disconnected as she left it, reboots start it disconnected until connect-on-boot is on, then connected; uninstall leaves no unit, binary, group, process, /run/thinkpol*, TUN, guard table, policy rules, and resolv.conf as before, also after a reboot; the state directory stays. Mutations seen failing in the lab: Restart=no, the runtime directories kept, the toggle writing nothing. Unit tests (fake systemctl/launchctl with state): TestInstallUnderSystemd, TestInstallUnderLaunchd, TestUninstallLeavesNothingOfTheService, TestInstallRefusesBeforeChangingAnything, TestADefinitionChangedByHandIsNotInstalled; mutations seen failing: the user not added, the group kept, an edited definition accepted, no bootstrap retry, Ready ignored, the trust check skipped, records removed with the locks, the toggle restarting, connect-on-boot on by default
- 2026-10-22 slice 3, the launchd plist as files: TestPlutilReadsTheLaunchdPlist (`plutil -lint` and `plutil -convert json -o -` on a copy in the test's directory, both connect-on-boot values), TestTheLaunchdPlistRunsTheAgentAndRestartsIt (a reader of the test's own: the keys, KeepAlive, no log paths), TestTheSystemdUnitRunsTheAgentAndRestartsIt (no RuntimeDirectory=); mutations seen failing: KeepAlive false, a StandardErrorPath, a malformed tag, RuntimeDirectory=thinkpol, the plist's THINKPOL_CONNECT flipped. The launchd install flow itself (launchctl, dseditgroup) is tested against a fake launchctl in slice 2; on a Mac it is a device step
