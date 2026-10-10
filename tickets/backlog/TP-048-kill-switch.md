---
id: TP-048
title: "Kill switch"
milestone: M5
area: platform
repo: thinkpol-vpn
size: L
depends_on: [TP-046, TP-047]
refs: [D4]
owner: ""
branch: ""
---

## Goal
With the kill switch on, nothing leaves the device when the tunnel is down.

## Scope
- Firewall rules per OS: pf anchor (macOS), nftables (Linux), WFP (Windows): only entry endpoints allowed, plus LAN with allow-LAN.
- Temporary pause for captive portals.
- Rules stay in place if the service crashes, until it restores them.

## Acceptance
- [ ] killing the service with the kill switch on leaves no traffic flowing except to entries, on all three OSes

## Log
- 2026-10-10 created in backlog
