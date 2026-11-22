---
id: TP-278
title: "The supervisor serves a listener before its workers know it"
milestone: M2
area: agent/supervisor
stream: core
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
A shared listener the supervisor opens is served only once every worker knows its id, so an authenticated client's first connection after a server starts (or after a map adds a listener) is served, not dropped.

## Scope
- `sharedListeners.open` (`internal/agent/supervisor/shared.go:436-443`) starts `serveStreams` (or `serveDatagrams`) as soon as the listener opens, while `setListeners` is still opening the rest of the set.
- `SetListeners` signals each worker's `listenersChanged` only after `setListeners` returned (`internal/agent/supervisor/supervisor_linux.go:561-568`), so a worker learns the new ids later still.
- A worker that gets a stream for a listener id it doesn't know closes it (`internal/agent/worker/shared.go:190-194`, counted in `unknownListener`).
- Effect: an authenticated client whose first hello arrives during that window gets "TLS handshake: EOF" (on reality its target connection is dialed, then dropped). Probers are unaffected: what isn't authenticated is spliced in the supervisor. Seen in TP-230's lab runs as device-a's first IPv4 dial failing 7 ms before the worker logged "listening shared 1". Exists on rewrite.
- Fix sketch: `open` doesn't serve; `SetListeners` sends each worker its Listeners message synchronously (the worker acknowledges it), then starts serving the listeners it opened.

## Out of scope
- A server's status and "map applied" line coming before its listeners serve: TP-279.

## Acceptance
- [ ] A test connects during a multi-listener open (a connection accepted on the first listener while later ones are still opening) and is served, not closed as an unknown listener; it fails on the current code.
- [ ] The supervisor's package doc says when a listener starts serving.

## Notes
- Found in TP-230's fix round (2026-11-22).

## Log
- 2026-11-22 created in backlog (from TP-230's review)
