---
id: TP-013
title: "Allow-ingress and allow-egress node settings"
milestone: M1
area: netmap
repo: thinkpol-vpn
size: M
depends_on: [TP-003, TP-010]
refs: [N8]
owner: agent-tp-013
branch: tp-013-ingress-egress
---

## Goal
Every server node has allow-ingress and allow-egress settings, both off by default; with ingress off the node is invisible to devices.

## Scope
- Fields in the map section; supported by the dev spec.
- Listener enforcement: with ingress off, device credentials are treated as unauthenticated (camouflage); only other nodes get in.
- The map builder never writes an ingress-off node's address into a device's section, and fails if a spec asks a device to connect to one.
- The egress flag is consumed by TP-014.

## Acceptance
- [ ] in the lab, a device can't connect to an ingress-off node even when it knows the address
- [ ] `map inspect` of a device section shows no address of an ingress-off node

## Notes
- From TP-003: `netmap.InboundLink.PeerKind` tells the listener whether a peer is a device or a server, so an ingress-off node can treat device credentials as unauthenticated. Add `allow_ingress`/`allow_egress` to `NodeSettings` (schema, Go type, both conversions, Build policy, the test fixture).
- **From TP-010 (ingress off):** put the filter inside `dataplane.AcceptedInbound`. With ingress off, drop entries whose `netmap.InboundLink.PeerKind` is a device, so they become unauthenticated (camouflage). The engine and the supervisor then both apply it, so the two tables can't disagree.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 docs (TP-003 review): notes on inbound peer kinds and adding the settings
- 2026-10-11 docs (TP-010 review): notes from the shared listener
- 2026-10-12 backlog → in-progress — owner: agent-tp-013, branch: tp-013-ingress-egress
