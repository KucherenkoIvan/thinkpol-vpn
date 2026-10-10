---
id: TP-014
title: "Egress on Linux"
milestone: M1
area: dataplane/egress
repo: thinkpol-vpn
size: M
depends_on: [TP-009, TP-013]
refs: [R1, DESIGN#ipv6]
owner: ""
branch: ""
---

## Goal
Nodes that allow egress forward a space's internet traffic, IPv4 and IPv6, and nothing leaks across spaces.

## Scope
- Forwarding inside the space's namespace, out through its veth; masquerade once in the root namespace (nftables via a pure-Go library such as `google/nftables`).
- IPv6: NAT66 when the VPS has IPv6, otherwise reject with ICMPv6 unreachable so clients fall back fast.
- Nodes without egress drop internet-bound traffic.
- Full cleanup on stop.

## Acceptance
- [ ] in the lab, a device fetches from the `internet` target through `server-2` (IPv4, and IPv6 where the lab has it)
- [ ] an egress-off node refuses the same traffic

## Log
- 2026-10-10 created in backlog
