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
- From TP-006 (path layer API in its ticket's Notes): one `path.NewNode` per space worker with `Options.Space` set, `Update(dataplane.PathConfigFrom(section, registry).Table)` on each map, `Serve(name, listener)` per listener; one `NewBind()` per WireGuard device, all devices' peers set in one `Node.SetPeers` call so a peer can move between devices. A peer key lives in exactly one device: a chain's exit is a peer of that chain's device only. `Release` a Bind with its device.
- WireGuard peers get `endpoint=<node id hex>`, never a UDP address; no `listen_port`; never `fwmark` (the Bind's `SetMark` refuses it, so `Up` fails loudly).
- MTU: `path.MessageBudget(outerMTU, 28 or 48, transport.Overhead)` per link; the TUN MTU is the minimum over the node's links minus 32 (WireGuard's data overhead), e.g. 1330 for a 1500-byte outer IPv6 path over udp. Refuse IPv6 on the overlay when that is below 1280, and surface it in status.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): notes on what the map reader does not guarantee
- 2026-10-10 docs (TP-006 review): notes from the path layer
