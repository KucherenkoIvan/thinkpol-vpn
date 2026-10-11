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

## Notes
- **From TP-011's review (deferred here):**
  - **A MapSource seam.** Today two producers feed one latest-wins channel of envelopes: `mapWatcher` (file poll + SIGHUP, `internal/agent/watch.go`) and, in a worker, the supervisor's configs. Gossip and push add more. Introduce a `MapSource` port with a multi-producer `latest[T]` whose `Put` never blocks (replace a pending value), and `Node.Sources` (file watcher, gossip, push) feeding it.
  - **One `follower.take`.** Device mode (`runner.next` in `dataplane.go`) and server mode (`serverSpaces.next` in `node.go`) each run `(*Map).Next` → `openSection` → removed/back-in-space logic. Fold them into one `follower` (current map, section, removed flag) with a single `take(envelope)` both modes call, so the semantics can't drift.
  - **Persisting.** When a node takes a newer map from the network, write `map.bin` atomically (temp file in the state directory, fsync, rename, fsync the directory, as `devmap.WriteMap` does) under the state directory's rules (owner, no group/other write; `internal/agent/state.go`). The file watcher then sees its own write and `Next` ignores it (`ErrNotNewer`).
  - **First boot without a map:** `thinkpol up` refuses to start without a valid `map.bin` today. A freshly provisioned node (TP-038) has `node.key` and `space.pub` but no map until the controller publishes one; either provisioning writes the first map, or `up` learns to wait idle for one from gossip/push (the removed-from-space idle state is the model).

## Log
- 2026-10-10 created in backlog
- 2026-10-11 docs (TP-011 review): notes on a MapSource seam, one follower for both modes, persisting maps, first boot
