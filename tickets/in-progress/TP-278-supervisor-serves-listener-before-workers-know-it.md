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
owner: agent-tp-278
branch: tp-278-serve-after-workers-know
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
- Design (2026-11-22): the worker answers each Listeners message with the ids it now has (`ipc.KindListenersKnown`, protocol version 6), sent from its control reader right after `sharedListeners.update`. Ordering on the control socket alone would cover streams but not datagrams (the data socket is separate), hence an explicit acknowledgement.
  - `shared.openListeners` (was `setListeners`) opens without serving; `SetListeners` signals every worker, then `shared.serveOpened` starts serving each new listener once every attached worker of a space that may be routed it (`ipcListeners`) has acknowledged it.
  - A worker that doesn't acknowledge within `StopTimeout`: the listener is served anyway (one stuck space must not hold every other space's listener; that worker is killed when its own send times out, and a restarted one has the listener from its start). Keeping it unserved and retrying was rejected for that reason.
  - A new worker process is attached (routed to) only once it has acknowledged every listener it may be routed (`shared.attachKnowing`, under `s.mu`, so a listener opened later waits for it too); a Listeners message it leaves unanswered for `StopTimeout` kills it (exit `unresponsive`). A worker restarting mid-update gets the current set in its first Listeners and is attached only once it acknowledged it.
  - A listener closed while waiting is never served (it leaves `s.listeners` under `s.mu`; `openListeners` and `close` wake the waiter). Listeners kept across a retry keep serving; a kept one not yet served is served by whichever `serveOpened` gets there.
  - The prober path is unchanged: what isn't authenticated is still spliced or dropped in the supervisor; a listener not yet served leaves connections in its backlog for at most `StopTimeout`.

## Log
- 2026-11-22 created in backlog (from TP-230's review)
- 2026-11-22 backlog → in-progress, owner: agent-tp-278
- 2026-11-22 implemented (b3e2e8d3), unit tests and mutations on the Mac green; remote lint/test and lab runs pending a quiet runner (handoff: run them, tick the boxes, move to review)
