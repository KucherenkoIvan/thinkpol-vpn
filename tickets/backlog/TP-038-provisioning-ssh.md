---
id: TP-038
title: "Provisioning over SSH"
milestone: M4
area: features/provisioning
repo: thinkpol-vpn
size: L
depends_on: [TP-034]
refs: [A4, S2]
owner: ""
branch: ""
---

## Goal
`thinkpol node add root@host` turns a fresh Linux box into a node, and re-running it repairs the node.

## Scope
- Idempotent steps: upload the binary, systemd unit, sysctls, base nftables, volatile journald, state dir permissions, key generation on the node, public key retrieval, add to the space with ingress and egress off, publish.
- `thinkpol node set <node> --ingress --egress`.
- A dry-run mode printing the plan.

## Acceptance
- [ ] a fresh lab container becomes a working node with one command; running it again changes nothing

## Notes
- **Shaping rollout (TP-027):** the controller puts shaping, or a new shaping field or value, into a link only when both ends' nodes reported supporting it (DESIGN "Transports own traffic shape"). Provisioning registers the node with its agent version and capabilities, so the first map it gets carries only shaping it supports.

## Log
- 2026-10-10 created in backlog
