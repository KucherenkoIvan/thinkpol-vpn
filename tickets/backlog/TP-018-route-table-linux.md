---
id: TP-018
title: "Route-table enforcement on Linux"
milestone: M1
area: dataplane/netcfg
repo: thinkpol-vpn
size: M
depends_on: [TP-007, TP-015, TP-016]
refs: [R2, DESIGN#routing-rules-and-dns]
owner: ""
branch: ""
---

## Goal
On Linux devices, `direct` destinations go straight out and everything else enters the tunnel, using the OS routing table.

## Scope
- Install `direct` prefixes via the physical gateway; send everything else into the TUN (split defaults such as `0.0.0.0/1` + `128.0.0.0/1`, and the IPv6 equivalents).
- Always keep entry nodes' endpoints outside the tunnel (routing-loop prevention).
- Watch for physical gateway changes (netlink route events) and re-apply.
- Full cleanup on disconnect.

## Acceptance
- [ ] in the lab, a destination in a `direct` range is reached outside the tunnel (visible in plaintext at the router), others only through it
- [ ] changing the device's gateway re-applies routes without a reconnect

## Log
- 2026-10-10 created in backlog
