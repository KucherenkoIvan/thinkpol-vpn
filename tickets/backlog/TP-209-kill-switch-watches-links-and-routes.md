---
id: TP-209
title: "Kill switch re-applies on link and route changes"
milestone: M3
area: dataplane/firewall
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-048]
refs: [D4, RR61]
owner: ""
branch: ""
---

## Goal
On Linux, a bridge that becomes the uplink (a port enslaved, a default route moved onto it or a port, a VLAN on top of it) stops passing what it bridges at once, not at the next re-apply (up to about 15 s today, RR61).

## Scope
- Watch link and route changes (netlink subscriptions, after the netcfg watch's pattern) and re-apply the kill switch when a bridge's ports, uppers or routes change; debounce bursts.
- The same watch closes the DHCP-pending case RR61 names (a veth uplink whose default route appears after the listing).
- docs: firewall doc.go, RR61.

## Out of scope
- The netdev egress chain (TP-206).

## Acceptance
- [ ] lab: a bridge on its own passes within it; a default route moved onto it is refused within a second, well before the 10 s tick (lab test, mutation-checked: the watch off → still passing after a second)
- [ ] a burst of link changes re-applies a bounded number of times (unit or lab test)

## Notes
- From TP-048's review rounds 3 and 4 (RR61).

## Log
- 2026-11-12 created in backlog (from TP-048's review)
