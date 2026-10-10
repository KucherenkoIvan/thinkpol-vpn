---
id: TP-008
title: "TUN, WireGuard and the overlay router"
milestone: M0
area: dataplane
repo: thinkpol-vpn
size: L
depends_on: [TP-006, TP-007]
refs: [N1, N2, C1, DESIGN#data-plane]
owner: ""
branch: ""
---

## Goal
Packets written to the overlay interface reach the right peer through WireGuard and the path layer, and back.

## Scope
- TUN via `wireguard-go/tun` (Linux now).
- Router reading the TUN and dispatching to WireGuard devices through virtual `tun.Device`s, structured for one WireGuard device per egress (only the overlay device for now).
- WireGuard devices configured from the node's map section: peers, allowed IPs = overlay addresses, dual-stack.
- No WireGuard UDP socket is ever opened: the Bind is the path layer.

## Acceptance
- [ ] two nodes in separate namespaces ping each other over overlay IPv4 and IPv6
- [ ] the router is ready for several WireGuard devices (test with two dummy egress devices)

## Notes
- From TP-003's review: `netmap`'s reader (`(*Map).Open`) checks only that a section is well formed. It accepts what only `netmap.Build` rejects: repeated or overlapping overlay addresses, addresses outside the overlay, empty `Paths`, `NextHops` or `Endpoints`, invalid (zero) `netip.AddrPort`s, and routing loops across several nodes. Don't assume them away: never configure overlapping WireGuard allowed IPs (refuse a peer whose addresses collide with another peer's or the node's own, or fall outside the overlay), and tolerate peers without usable paths.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): notes on what the map reader does not guarantee
