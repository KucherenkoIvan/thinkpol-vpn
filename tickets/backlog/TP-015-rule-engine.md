---
id: TP-015
title: "Routing rule engine"
milestone: M1
area: dataplane/router
repo: thinkpol-vpn
size: M
depends_on: [TP-008]
refs: [R2, R3, DESIGN#routing-rules-and-dns]
owner: ""
branch: ""
---

## Goal
Ordered routing rules decide per destination whether traffic goes direct, through a chain, or is blocked.

## Scope
- Rule model: ordered, first match wins; matchers `default`, `cidr`, `geoip`; domain matchers parsed and kept but reported as not enforced in route-table mode.
- Actions `direct`, `chain:<name>`, `block`; at M1 a chain is a single egress node.
- Space defaults from the map, per-device overrides from a local file; presets "everything" and "all but domestic".
- Compiled into a longest-prefix-match table (IPv4 + IPv6) for the router, and into the set of `direct` prefixes for route-table enforcement.

## Acceptance
- [ ] table-driven tests cover overlapping prefixes, IPv6, override precedence and presets

## Log
- 2026-10-10 created in backlog
