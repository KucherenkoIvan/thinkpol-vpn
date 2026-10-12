---
id: TP-059
title: "Overlay interface re-applied after TUN link bounce"
milestone: M1
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: [TP-018]
owner: agent-small-fixes
branch: tp-059-overlay-reapply-on-link-event
---

## Goal
When the overlay TUN goes down and up, Linux drops its IPv6 addresses (and the link state can reset the MTU). The overlay interface configuration (addresses and MTU) is re-applied on link events, not only on the next map. Today the route table is re-applied on link events since TP-018, but the overlay's IPv6 stays gone until the next map arrives. Nothing leaks in that window (the route table and the blocking rules still hold), but the overlay is dark until a new map, which is wrong after a plain link bounce.

## Scope
- Watch the TUN's link events (netlink, as TP-018 does for the route table) and, on a link going up or coming back after down, re-apply the overlay configuration through the configurator (`netcfg`): addresses, IPv6 on/off, MTU.
- Debounce like the route-table re-apply, so one bounce causes one re-apply.
- Log the re-apply at info level with the reason ("link event"), and count it in status if that is cheap.

## Out of scope
- Route table re-apply (already done in TP-018).
- Platforms where the OS configures the TUN (VpnService, NetworkExtension): the engine's `Interface` is nil there and nothing changes.

## Acceptance
- [x] unit test: a link-down/up event on the overlay TUN triggers exactly one interface re-apply with the current addresses and MTU
- [x] lab test: bounce the TUN (`ip link set down` then `up`) in a namespace; overlay IPv6 comes back and pings over IPv4 and IPv6 recover, with no new map applied
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- Route table re-apply on link events is TP-018's; reuse its subscription and debounce.
- **Done:** the router passes on the TUN's link-up events (`Router.LinkUp()`, a coalesced signal on every `tun.EventUp`; before, it drained them all). With an `Interface`, the engine runs a watcher (`internal/dataplane/interface.go`) that, after each burst of them (200 ms debounce, as the route table's watcher), re-applies the interface configuration the last Apply put in place (addresses, so IPv6 on or off as the section had it, and MTU) through the same netcfg configurator, under the engine's `serial` lock so it never runs with an Apply or Close. The re-apply sets `Up: false` (leave the link state alone): it reacts to the link coming up, and a link someone took down again meanwhile stays down (the route table's unreachable default holds then). A failed re-apply is logged and retried every 5 s; a success is logged at info (`overlay interface re-applied reason="link event"`) and counted: `Status.InterfaceReapplies`, local API counter `interface.reapplies` (kept out of `thinkpol status`'s "dropped"). `Close` stops the watcher before it closes anything. DESIGN.md "IPv6" (the overlay bullet) says so.
- **Why the TUN's own events, not `netcfg.Watch`:** `Watch` signals any link, route and rule change in the namespace without saying which, so it can't tell a link coming up from one going down; re-applying on a down would either bring the TUN back up (fighting whoever took it down, and the route table's lab test, which checks the status while the TUN is down) or add addresses to a down link for nothing. wireguard-go's TUN reports `EventUp` for its own link only, in its own namespace (worker namespaces too). `netcfg` and `routetable` are unchanged, so nothing here touches TP-057's files.
- **Limits:** wireguard-go also reports `EventUp` on other changes of a running link (an MTU change) and when the first Apply brings the link up, so a node logs one re-apply right after it starts (and after a map that changes the MTU); those re-applies change nothing (netcfg converges), and the counter says "most change nothing" like the route table's. A bounce slower than wireguard-go's 1 s link poll can add a second `EventUp`, hence a second, empty re-apply.
- **For TP-057 (coordination):** `lab/routetable_test.go` says, before its TUN bounce, "Last in this run: a TUN that goes down loses its IPv6 addresses until the next map re-applies them". After this ticket the engine puts them back when the link comes up, so that comment is stale. TP-057's branch edits that file, so it is left alone here: whichever of the two merges second drops the remark (the bounce no longer has to come last).
- **Tests:** `TestALinkBounceReappliesTheInterface` (fake configurator, a virtual TUN whose link events the test sends: a down/up gives exactly one re-apply with the applied addresses and MTU, logged and counted; a down alone and Close re-apply nothing), `TestALinkEventBeforeTheFirstApplyChangesNothing`; lab `TestTheOverlayComesBackAfterALinkBounce` (`engine_lab_test.go`, M0 in namespaces on real TUNs: `ip link set down` drops device-a's IPv6 address, the MTU is set to 1400 while down, `up`; the address and MTU 1328 come back, and pings to server-1 and device-b over IPv4 and IPv6 pass with no Apply). Without the watcher both the unit and the lab test fail (checked). The namespace M0 setup moved into `startM0InNamespaces`, shared with `TestNamespacesPingOverTheOverlay`.

## Review findings
Nits from review; the orchestrator's decisions.

- [ ] R1 Count `ifcReapplies` only on a successful re-apply.
- [ ] R2 Don't retry while the link is down; log only the first failure of a persistent failure.
- [ ] R3 A short cooldown after each re-apply.
- [ ] R4 Test: an Apply with a new section racing a pending link event (the re-apply carries the new configuration).
- [ ] R5 Test: a fake Interface failing once (the re-apply is retried).
- [ ] R6 Drop the stale "TUN bounce comes last" remark in `lab/routetable_test.go`.

## Log
- 2026-10-12 created in backlog
- 2026-10-12 backlog → in-progress — owner: agent-small-fixes, branch: tp-059-overlay-reapply-on-link-event
- 2026-10-12 in-progress → review — every acceptance box checked; `make lint`, `make test` (one unrelated `blobs` TestATricklingPeerIsAbandoned flake under load, 10/10 alone, then a green run), `go test -race` on dataplane, router and localapi, and `make lab-test LAB_P=2` (lab tests and 28 packages in lab nodes) pass
- 2026-10-13 review → has-errors — review nits R1–R6 (see Review findings)
- 2026-10-13 has-errors → in-progress — owner: agent-small-fixes, picking up the review findings
