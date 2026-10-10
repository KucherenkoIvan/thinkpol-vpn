---
id: TP-017
title: "Blob distribution through the overlay"
milestone: M1
area: dataplane/blobs
repo: thinkpol-vpn
size: M
depends_on: [TP-011, TP-016]
refs: [R9, A9]
owner: ""
branch: ""
---

## Goal
Nodes get the list files (and later releases) referenced by their map from peers, without any outside server.

## Scope
- Simple request/response service on overlay addresses: fetch blob by hash.
- Verify the hash, cache in the state dir, serve cached blobs to peers.
- Fetch on map change; keep serving the previous version until the new one is verified.

## Acceptance
- [ ] in the lab, a device without the list fetches it from a server node
- [ ] a corrupted blob is rejected and fetched again from another peer

## Log
- 2026-10-10 created in backlog
