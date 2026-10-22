---
id: TP-044
title: "Signed agent updates"
milestone: M4
area: agent
repo: thinkpol-vpn
size: M
depends_on: [TP-037, TP-017]
refs: [A9]
owner: ""
branch: ""
---

## Goal
Nodes update themselves from signed releases distributed through the network (should-have).

## Scope
- Release signing key; signed release manifests distributed as blobs.
- Agent self-update with rollback if the new version fails to start.

## Acceptance
- [ ] a bad release rolls back automatically in the lab

## Notes
- **Shaping rollout (TP-027):** the controller puts shaping, or a new shaping field or value, into a link only when both ends' nodes reported supporting it (docs/design/transports.md). After an update the agent reports its new version and capabilities; the controller turns on newer shaping for a link only once both ends have updated and reported.
- **From TP-017:** reuse `internal/dataplane/blobs` for releases: a new `BlobKind` (old nodes hold and pass unknown kinds by hash) and the release-key check after `blobs.Check`. Releases are tens of MB: raise `Limits.MaxBlob`/`MaxHeld` for that kind and stream to disk instead of buffering in memory (the protocol resumes from an offset; transfers get `DialTimeout + size/MinRate`). Seeds go to workers as one sealed memfd each (`ipc.KindBlob`, at most `ipc.MaxBlobSize` = 16 MiB): raise it, or have the supervisor serve releases itself.
- **Signing key anchor (independent design review, 2026-10-13; TP-062):** the update signing key is pinned on a server when provisioning installs it over SSH (TP-038), which is the anchor; a device's anchor is for this ticket to decide with the invite (TP-039). A node whose update fails the signature check keeps running its current binary and never bricks.

## Log
- 2026-10-10 created in backlog
- 2026-10-12 docs (TP-017): notes from blob distribution
- 2026-10-13 docs (TP-062): note: update key pinned at provisioning; a failed signature keeps the node running
