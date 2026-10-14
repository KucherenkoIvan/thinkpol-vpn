---
id: TP-076
title: "Kill switch (Windows)"
milestone: M5
area: dataplane/firewall
repo: thinkpol-vpn
size: M
depends_on: [TP-047, TP-048]
refs: [D4]
needs_human: windows
owner: ""
branch: ""
---

## Goal
With the kill switch on, nothing leaves a Windows device when the tunnel is down, matching macOS and Linux behaviour from TP-048.

## Scope
- Windows Filtering Platform (WFP) kill-switch rules: only entry endpoints allowed, plus LAN with allow-LAN.
- Temporary pause for captive portals.
- Rules stay in place if the service crashes, until the service restores them (same acceptance themes as TP-048, on Windows).

## Out of scope
- pf (macOS) and nftables (Linux) — TP-048.
- Wintun and the rest of the Windows data plane — TP-047.

## Acceptance
- [ ] killing the service with the kill switch on leaves no traffic flowing except to entries (and LAN with allow-LAN), on Windows
- [ ] after the agent crashes with the "everything" or "all but domestic" preset and the kill switch off, fail-closed behaviour matches TP-048 on Windows until the agent starts and connects again
- [ ] deliberate disconnect with the kill switch off removes the guard; with the switch on it stays

## Notes
- Split from TP-048 (independent review 2026-10-15): Windows half gated on TP-047 and a real Windows test host.

## Log
- 2026-10-15 created in backlog
