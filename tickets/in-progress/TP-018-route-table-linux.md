---
id: TP-018
title: "Route-table enforcement on Linux"
milestone: M1
area: dataplane/netcfg
repo: thinkpol-vpn
size: M
depends_on: [TP-007, TP-015, TP-016]
refs: [R2, DESIGN#routing-rules-and-dns]
owner: "agent-tp-018"
branch: "tp-018-route-table-linux"
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

## Notes
- netcfg (TP-007) manages the main table only: per-space namespaces each have their own. If enforcement needs policy routing (ip rules + extra tables), add `Table` and rules to the netcfg port here. See TP-007's Notes for `DefaultRoute`, split defaults and delete-then-add on route changes.
- **From TP-016 (lists):** `lists.Set.Prefixes()` is already the merged minimal CIDR list (overlapping and adjacent merged), IPv4 then IPv6. RU is ~23k prefixes (DB-IP Lite 2026-10: 12,895 IPv4 + 10,088 IPv6). Lists never hold IPv6 inside `::ffff:0:0/96`, so no IPv6 route can capture IPv4.
- **Any coarsening (e.g. a route budget for Windows, TP-047) may only shrink the direct set, never grow it:** drop or split direct prefixes, never widen one. Growing would send foreign traffic outside the tunnel, in the clear in front of the censor; shrinking only sends some domestic traffic through the tunnel. Put it in `internal/lists` with a test that the result `Minus` the original is empty.
- From TP-006: links' sockets are marked by the transport adapter (`udp.Options.Control`), never by WireGuard (no `fwmark` on any WireGuard device; the path layer's Bind refuses marks). Linux: `SO_MARK` plus an `ip rule` sending marked traffic to the main table. Darwin: `IP_BOUND_IF`/`IPV6_BOUND_IF` to the physical interface. Windows: `IP_UNICAST_IF`. TP-011 builds the Registry with that Control.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 notes from TP-016 review: route count and the shrink-only rule for coarsening
- 2026-10-10 docs (TP-006 review): notes from the path layer
- 2026-10-12 backlog → in-progress — owner: agent-tp-018, branch: tp-018-route-table-linux
