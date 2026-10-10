---
id: TP-020
title: "DNS resolver"
milestone: M1
area: dataplane/dns
repo: thinkpol-vpn
size: L
depends_on: [TP-011, TP-015]
refs: [N3, R4, DESIGN#routing-rules-and-dns]
owner: ""
branch: ""
---

## Goal
DNS follows the routing rules: overlay names resolve, `direct` domains use a domestic resolver, everything else resolves through the tunnel, and nothing leaks.

## Scope
- Resolver on the node's overlay address (e.g. `miekg/dns`): answers `<device>.<space>.internal` (A and AAAA) from the map.
- Forwarding: domains with a `direct` rule to the domestic upstream; everything else through the tunnel to a resolver at the egress node.
- OS integration with restore on shutdown: Linux (systemd-resolved over D-Bus, `resolv.conf` fallback), macOS (`scutil` / `/etc/resolver`).

## Acceptance
- [ ] lab capture: no DNS query leaves the device outside the tunnel except to the domestic upstream for `direct` domains
- [ ] overlay names resolve on Linux and macOS

## Log
- 2026-10-10 created in backlog
