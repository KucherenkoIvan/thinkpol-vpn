---
id: TP-037
title: "Map gossip and push channel"
milestone: M4
area: netmap
repo: thinkpol-vpn
size: M
depends_on: [TP-036, KRN-002]
refs: [A5, DESIGN#the-signed-map]
owner: ""
branch: ""
---

## Goal
New maps reach every node, from the controller or from each other, and nodes run on the last valid map whatever happens.

## Scope
- Nodes exchange envelope versions with peers and pull newer ones.
- The controller pushes over a grpckit stream to connected nodes.
- Last valid map kept across restarts.
- Guest-space envelopes accepted only for granted workers (together with TP-040).

## Acceptance
- [ ] with the controller off, a map change made before it went down still reaches a node that was offline, through its peers

## Log
- 2026-10-10 created in backlog
