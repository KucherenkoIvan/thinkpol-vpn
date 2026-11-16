---
id: TP-233
title: "The macOS kill switch's self-check doesn't check its IPv6 passes' values"
milestone: later
area: dataplane/firewall
stream: core
repo: thinkpol-vpn
size: S
depends_on: []
refs: [D4]
owner: ""
branch: ""
---

## Goal
After loading, the macOS kill switch reads its rules back and checks them (`checkListed`, internal/dataplane/firewall/pfctl_darwin.go:855), but for the IPv6 housekeeping passes (internal/dataplane/firewall/killswitch_darwin.go:311-313) it only checks words like `inet6`, `udp`, `547` and `icmp6-type`, not the DHCPv6 destinations (`ff02::1:2`, `fe80::/10`) or the ICMPv6 type numbers. If pf loaded different values, the self-check would not notice. Found by the IPv6 proxy-proof review (2026-11-16).

## Scope
- checkListed requires the DHCPv6 destinations and the ICMPv6 type numbers the rules name.

## Out of scope

## Acceptance
- [ ] checkListed requires the DHCPv6 destinations and every ICMPv6 type number the rules name; tests with a fake pfctl listing a wrong value; mutation-checked.

## Notes
- After the MVP (orchestrator default, 2026-11-16).

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
