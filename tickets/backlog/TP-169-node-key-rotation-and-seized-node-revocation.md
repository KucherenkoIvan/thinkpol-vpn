---
id: TP-169
title: "Node key rotation and revocation of a seized node"
milestone: later
area: control-plane
repo: thinkpol-vpn
size: L
depends_on: []
refs: [RR56, docs/design/security.md#node-safety]
owner: ""
branch: ""
---

## Goal
An admin can rotate a node's keys, and revoke a seized node so that its keys stop working everywhere, through the map. Today a seized node's keys stay valid until someone builds a map without it by hand (RR56).

## Scope
- Rotating a node's keys: new keys generated on the node (never copied off), the new public key reaching the controller, a map that switches the node's links over, the old keys refused afterwards.
- Revoking a node: the controller publishes a map without it; every peer drops its links; the revocation spreads by gossip once one honest node is reachable.
- The design written into docs/design/security.md and control-plane.md before it is built; RR56 narrowed or closed.

## Out of scope
- The space's signing key and the recovery key: TP-036 (RR47).
- Device keys in the OS keystore: TP-170.
- Ephemeral nodes: after the MVP.

## Acceptance
- [ ] lab: a node's keys rotated; its links come back on the new keys, and a peer refuses the old ones
- [ ] lab: a revoked node's links are dropped by every peer once the map reaches them; the revoked node can't link again with its keys
- [ ] RR56 updated (narrowed or struck through with this ticket)
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Source: TP-139 owner session, 2026-11-07.
- owner 2026-11-07: documented now, built after the concept is proven.
- Related: TP-036 (publishing and recovery: the signing key's rotation, RR47).

## Log
- 2026-11-07 created in backlog
- 2026-11-07 milestone → later (owner's MVP cut: owner: security after the concept is proven)
