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

## Notes
- **From TP-014 (egress):** an exit's resolver for its space's devices runs in the space's worker namespace, so its upstream queries leave by the space's egress like any other traffic (masqueraded, through the root namespace's egress rules): a relay without egress can't resolve internet names at all. The node's own stub (127.0.0.53) and link-local provider resolvers (169.254.x, fd00:ec2::253 and alike) are unreachable from a space by design (egress refuses loopback, link-local and private destinations unless `EgressAllowed` names them): give the resolver public upstreams.

## Log
- 2026-10-10 created in backlog
- 2026-10-12 docs (TP-014 review): notes from egress on Linux
