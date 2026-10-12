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
- [x] in the lab, a destination in a `direct` range is reached outside the tunnel (visible in plaintext at the router), others only through it — `lab/routetable_test.go` `TestRouteTableSendsOnlyDirectAroundTheTunnel` (map `lab/maps/routetable.yaml`): a "domestic" site (198.51.100.7, 2001:db8:d0::7 on the `internet` node) and a "foreign" one (203.0.113.7, 2001:db8:ab::7 on an added `abroad` node), routed by the lab's routers; the space's domestic list `dm` (built with `dev lists build`) reaches device-a through the overlay from server-1's seed; device-a switches to the "all but domestic" preset with `thinkpol rules preset all-but-domestic`. Domestic IPv4 and IPv6 pings are answered and show at the router with the device's own source, and never enter the TUN; pings to the foreign site enter the TUN (captured on `thinkpol0`; the router's `routed` counter rises by them), and no packet to it shows at the router or leaves the device outside the TUN, IPv4 and IPv6; the link's UDP shows at the router and never enters the TUN; `ip route get` on the device: domestic and endpoints out of eth, foreign into `thinkpol0`, foreign with mark 0x7470 out of eth. Switching to "everything" sends the domestic site into the TUN (nothing to it at the router) and back. With a 1300-byte link MTU (overlay IPv4-only) foreign IPv6 is unreachable and absent at the router while domestic IPv6 still goes direct. Each stop leaves `ip rule` and the routing tables as before. Until TP-014 the exit drops what the tunnel brings it (`NotLocal`), so the test asserts the TUN and the counters, not an answer from abroad. The router's `Direct` counter isn't a usable leak measure: the TUN's own link-local multicast (MLD, router solicitations) is `local` and counted there; the test checks captures instead. Also `internal/dataplane/routetable` `TestEnforcesInANamespace` (kernel lookups for direct, tunnel, marked, endpoint, overlay, LAN, IPv6 off and an MTU drop, repair of outside removals, clean Close) and `TestCountrySizedTable` (performance, below).
- [x] changing the device's gateway re-applies routes without a reconnect — same lab test: the device's IPv4 and IPv6 defaults move from `router` to `router-2`; domestic pings then show at `router-2`, the overlay keeps answering through the same process (no restart, no failed Apply in its log), and `route_table.reapplies` rises. Nothing in the table names the gateway, so the re-apply finds nothing to change (`TestEnforcesInANamespace` and `TestCountrySizedTable` check the table is unchanged and direct traffic follows the new gateway).

Evidence: `make lint`, `make test`, `make test-race`, `make lab-gotest` for netcfg, routetable and agent, and `make lab-test` (see Log).

## Notes
- netcfg (TP-007) manages the main table only: per-space namespaces each have their own. If enforcement needs policy routing (ip rules + extra tables), add `Table` and rules to the netcfg port here. See TP-007's Notes for `DefaultRoute`, split defaults and delete-then-add on route changes.
- **From TP-016 (lists):** `lists.Set.Prefixes()` is already the merged minimal CIDR list (overlapping and adjacent merged), IPv4 then IPv6. RU is ~23k prefixes (DB-IP Lite 2026-10: 12,895 IPv4 + 10,088 IPv6). Lists never hold IPv6 inside `::ffff:0:0/96`, so no IPv6 route can capture IPv4.
- **Any coarsening (e.g. a route budget for Windows, TP-047) may only shrink the direct set, never grow it:** drop or split direct prefixes, never widen one. Growing would send foreign traffic outside the tunnel, in the clear in front of the censor; shrinking only sends some domestic traffic through the tunnel. Put it in `internal/lists` with a test that the result `Minus` the original is empty.
- From TP-006: links' sockets are marked by the transport adapter (`udp.Options.Control`), never by WireGuard (no `fwmark` on any WireGuard device; the path layer's Bind refuses marks). Linux: `SO_MARK` plus an `ip rule` sending marked traffic to the main table. Darwin: `IP_BOUND_IF`/`IPV6_BOUND_IF` to the physical interface. Windows: `IP_UNICAST_IF`. TP-011 builds the Registry with that Control.
- **From TP-017:** a device's direct set changes when a list arrives or is replaced (the engine recompiles on the blob service's change signal, `Engine.ReloadRules`), not only on a new map: route-table updates must be incremental or atomic. During a list's replacement the previous version stays in force (`EngineConfig.StandIn`) until the new one is verified, across restarts too (the device's `blobs/index`).

**Done in TP-018 (2026-10-12).**

*Layout (Linux, per family; DESIGN.md "Routing rules and DNS", route table on Linux):*
```
rule 5300: lookup main suppress_prefixlength 0            proto 86
rule 5301: not fwmark 0x7470 lookup 29808 (0x7470)        proto 86
table 29808, proto 86:
  default dev thinkpol0                 (IPv6 only while the overlay carries IPv6)
  unreachable default metric 2048       (IPv6)
  throw <direct prefix>                 (the rules' direct set, minimal)
  throw <endpoint>/32, /128             (every endpoint the section dials)
```
- Policy routing instead of split defaults in main: direct traffic and endpoints are *thrown* to the main table, so they follow whatever physical default route is there. Nothing names the gateway: DHCP renewals, roaming and interface changes need no route change (the lab moves the gateway and nothing in the table changes), and there is no delete-then-add window. Marked sockets (the links') skip the table. The endpoint throws make links bypass the TUN even unmarked and keep strict `rp_filter` working (replies from an entry pass the reverse-path check through the main table); the cost is that any traffic to an entry's address goes around the tunnel, not only the link's.
- IPv6 never leaks: with the overlay IPv4-only (MTU < 1280, or no IPv6 address), or when the kernel drops the TUN's IPv6 route on an MTU change before the next Apply, IPv6 meets the unreachable default; only direct prefixes and endpoints leave. IPv4 has no such fallback: if the TUN vanishes (a crash), IPv4 goes out normally, as D4 wants with the kill switch off.
- Mark and table 0x7470, priorities 5300/5301 (`routetable.Mark`, `Table`, `PriorityMain`, `PriorityTunnel`).

*Ports and packages:*
- `netcfg`: `Route.Table` (0 = main), `Route.Type` (`RouteUnicast`, `RouteThrow`, `RouteUnreachable`), `Config.Rules []Rule{Family, Priority 1–32765, Table, Mark, Invert, SuppressDefaultRoutes}`, and `Configurator.Watch(ctx) (<-chan struct{}, error)`: coalesced signals when a main-table default route of no owner changes or the owner's own routes or rules are deleted (also by its own Apply). Routes are dumped across all tables by protocol; rules carry `FRA_PROTOCOL` (Linux ≥ 4.17) and are reconciled, taken over after a crash, undone and closed like routes. `Validate` checks tables (no 253–255 by number), types and rules. Tests: `policy_linux_test.go` (apply/repair/close, cancelled Apply, takeover of rules, Watch).
- `dataplane/routetable` (new): `Want{TUN, Direct *lists.Set, Bypass []netip.Addr, IPv6}`, `Config(Want) netcfg.Config` (pure, unit-tested anywhere), `Enforcer` (`Open(configurator, log)`, `New(log)` = `netcfg.New(OwnerRouteTable)`): `Enforce` skips an equal Want, pauses the watcher while it applies (its own events would only slow it), re-applies after `Watch` signals (200 ms debounce), `Status{Routes, LastApply, Reapplies}`, `Close` removes everything. `SocketControl()`: `SO_MARK` 0x7470 on Linux (a socket it can't mark fails to open), nil elsewhere.
- Engine: `EngineConfig.RouteTable` (interface: `Enforce`, `Status`, `Close`; owned once `NewEngine` succeeds, closed first in `Close`), `StepRouteTable`, `Status.RouteTable{Enforced, Routes, LastApply, Reapplies}`. Wherever the rules recompile (Apply, `SetRules`, `ReloadRules`): direct prefixes the new rules drop are removed *before* the router's table changes (`shrinkRoutes`), the new set goes in after (`growRoutes`); a failed removal falls back to nothing direct (everything into the TUN, where the router drops what it calls direct), and the next Apply retries. Endpoints come from the section's dialed links.
- Agent: device mode sets `DataPlane.RouteTable` (an Enforcer next to the overlay's configurator; its construction failing is `StartError{Step: "route table"}`); `Transports(markSockets bool)`: `true` in `Node.Run` (device, supervisor in the root namespace), `false` in workers (nothing routes into their TUN, and `SO_MARK` needs `CAP_NET_ADMIN` over the namespace, which older kernels check in the root user namespace). `map applied` logs `route_table_routes`; the local API's counters add `router.direct`, `route_table.routes`, `route_table.reapplies` (`thinkpol status` prints a route table line).
- Dev map spec: `chains: [{name, exit}]`, `rules: ["<match> -> <action>", ...]`, `presets: {domestic, chain}` go into every device's section; a `geoip:` rule or `presets.domestic` must name a spec list (TP-017's `lists`), and every device must name it in its own `lists` (the builder says so otherwise). The reference spec and golden show it all (device-b now has a path to server-3, the chain's exit, and the `ru` list).

*Performance* (lab node, an RU-sized set: 12,895 IPv4 /24s + 10,088 IPv6 /32s, none mergeable, plus the local ranges: 22,996 routes; `TestCountrySizedTable`): connect (first Apply) 1.65 s; a map moving one endpoint 0.30 s (one dump of the table and a diff); a gateway change: no route touched, one no-op re-apply; switching to "everything" (removing the country) 2.6 s; back 1.3 s; disconnect (Close) 1.3 s. Netlink costs ~60 µs per IPv4 add and ~90 µs per IPv6 delete; with the watcher subscribed during the Apply it was twice that, hence the pause. Batching netlink requests would cut it further if ever needed. The engine holds its lock during the Apply, so `Status` waits that long on connect.

*Gotchas:* `ip rule show protocol N` is not a filter in the lab's iproute2 (it lists every rule): check rules by priority. `ip -6 route get` to an unreachable route says "No route to host". Throw and unreachable IPv6 routes show `dev lo` in dumps; netcfg compares them by type only.

**For downstream tickets:**
- **TP-019 (macOS):** no policy routing there: implement the same `routetable.Want` with routes in the main table: split defaults (`0.0.0.0/1`, `128.0.0.0/1`, `::/1`, `8000::/1`) into the utun, direct prefixes and endpoints via the physical gateway from `DefaultRoute`, re-applied on `Watch` (a route socket listener) since there the routes do name the gateway; a TUN without IPv6 needs IPv6 rejected some other way (a reject route `::/1`+`8000::/1` to lo, or pf). `SocketControl` on darwin: `IP_BOUND_IF`/`IPV6_BOUND_IF` to the physical interface. `Enforcer` and the engine's ordering work as they are if `Config` gets a darwin variant (make `Config` per OS then).
- **TP-020 (DNS):** queries to the domestic upstream for `direct` domains must leave around the tunnel: mark their sockets with `routetable.SocketControl()` (or route the upstream's address as direct); everything else goes through the TUN by itself.
- **TP-021 (IPv6 leaks):** routing already drops IPv6 the TUN can't carry (the unreachable default) and sends the rest into the TUN; what is left is a firewall layer for what routing can't see (marked sockets, other tables, traffic before the first Apply). After a crash, the rules, the table and IPv6's unreachable default stay until the agent starts again and takes them over (IPv4 flows: the TUN's default went with the TUN); TP-046's unit can run a cleanup on stop.
- **TP-048 (kill switch):** allow the entries' endpoints (`Want.Bypass`, from the section's links) and the mark 0x7470; with the kill switch on, an IPv4 unreachable fallback in table 0x7470 (like IPv6's) would also keep IPv4 in while the TUN is gone, but outlives a crash: decide there.
- **TP-047 (Windows):** the shrink-only coarsening rule above stands; the engine's shrink-before/grow-after ordering applies to any route budget too.
- **TP-023 (M1 acceptance):** `lab/routetable_test.go` is the base for "direct vs tunneled"; once TP-014 merges, assert the foreign site answers through server-1. Lab networks are private ranges, which `local` (in every preset) sends around the tunnel: test sites need public-looking addresses (the test puts documentation addresses on lo and routes them on both routers).

## Log
- 2026-10-10 created in backlog
- 2026-10-10 notes from TP-016 review: route count and the shrink-only rule for coarsening
- 2026-10-10 docs (TP-006 review): notes from the path layer
- 2026-10-12 backlog → in-progress — owner: agent-tp-018, branch: tp-018-route-table-linux
- 2026-10-12 docs (TP-017): notes from blob distribution
