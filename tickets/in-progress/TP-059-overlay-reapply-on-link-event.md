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
- [ ] unit test: a link-down/up event on the overlay TUN triggers exactly one interface re-apply with the current addresses and MTU
- [ ] lab test: bounce the TUN (`ip link set down` then `up`) in a namespace; overlay IPv6 comes back and pings over IPv4 and IPv6 recover, with no new map applied
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Route table re-apply on link events is TP-018's; reuse its subscription and debounce.

## Log
- 2026-10-12 created in backlog
- 2026-10-12 backlog → in-progress — owner: agent-small-fixes, branch: tp-059-overlay-reapply-on-link-event
