---
id: TP-013
title: "Allow-ingress and allow-egress node settings"
milestone: M1
area: netmap
repo: thinkpol-vpn
size: M
depends_on: [TP-003, TP-010]
refs: [N8]
owner: ""
branch: ""
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

## Log
- 2026-10-10 created in backlog
