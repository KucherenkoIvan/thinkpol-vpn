---
id: TP-007
title: "Network config port and Linux adapter"
milestone: M0
area: dataplane/netcfg
repo: thinkpol-vpn
size: M
depends_on: [TP-001]
refs: [N1, DESIGN#ipv6]
owner: "agent-tp-007"
branch: "tp-007-netcfg-linux"
---

## Goal
One port for OS-level network setup (addresses, MTU, link state, routes), with a Linux adapter on netlink instead of shelling out.

## Scope
- Port: set IPv4 + IPv6 (ULA) addresses on an interface, MTU, up/down, add/remove routes (prefix via interface or gateway, routing table), default gateway per address family.
- Linux adapter on netlink (pure Go, e.g. `vishvananda/netlink`).
- Cleanup is part of the contract: the adapter records what it added and removes it on close, also after a partial failure.
- Tests run inside a network namespace (root needed; run in a lab container or skip).

## Out of scope
macOS (TP-019), Windows (TP-047), rule-driven route tables (TP-018).

## Acceptance
- [ ] addresses, MTU and routes applied and fully removed in the namespace test
- [ ] a failure halfway through leaves nothing behind

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-007, branch: tp-007-netcfg-linux
