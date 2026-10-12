---
id: TP-048
title: "Kill switch"
milestone: M5
area: dataplane/firewall
repo: thinkpol-vpn
size: L
depends_on: [TP-046, TP-047]
refs: [D4]
needs_human: windows
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

## Notes
- **From TP-014 (egress):** an exit without IPv6 refuses a device's IPv6 with ICMPv6 "no route" rather than dropping it; the kill switch still has to block IPv6 outside the tunnel on the device, and must let the tunnel's own transport sockets out whatever the rules.

## Log
- 2026-10-10 created in backlog
- 2026-10-12 docs (TP-014 review): notes from egress on Linux
