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
- [x] A test connects during a multi-listener open (a connection accepted on the first listener while later ones are still opening) and is served, not closed as an unknown listener; it fails on the current code. (`TestConnectionDuringOpenWaitsForTheWorkers`, `internal/agent/supervisor/shared_test.go`: the second listener's open is held while a member connects to the first; it fails with the old serve-in-`open` restored, M1 in the Log.)
- [x] The supervisor's package doc says when a listener starts serving. (`internal/agent/supervisor/doc.go` "Shared listeners"; the ipc and worker package docs gained the ListenersKnown answer.)

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
- 2026-11-22 done: workers answer each Listeners with the ids they hold (ipc.KindListenersKnown, protocol version 6); SetListeners opens without serving and serves each new listener once every attached worker that may be routed it has answered (StopTimeout bound, then served); a worker process is attached only once it has answered for every listener it may be routed, and killed if a Listeners goes unanswered for StopTimeout. Tests: TestConnectionDuringOpenWaitsForTheWorkers, TestWorkerAttachedOnceItKnowsTheListeners, TestUnacknowledgingWorkerHoldsUpNothingLong, TestListenerClosedWhileWaitingIsNotServed, TestListenersKnownRoundTrip
- 2026-11-22 mutations (each fails a new test, then restored): M1 open serves at once (the old behaviour) → TestConnectionDuringOpen…, TestUnacknowledging…, TestListenerClosed… fail; M2 serveOpened never waits → TestUnacknowledging…, TestListenerClosed… fail; M3 attachKnowing ignores the acknowledgement → TestWorkerAttachedOnce… fails; M4 the ack timeout returns without serving → TestUnacknowledging… fails; M5 openListeners doesn't wake the waiter → TestListenerClosed… fails
- 2026-11-22 runs on 17180e58 (rewrite 883b150c merged): make lint 0 issues and make test pass (exit 0); make lab-gotest PKG='./internal/agent/supervisor/... ./internal/dataplane/transport/reality/... ./internal/dataplane/transport/udp/...' ok (supervisor 54.6 s, reality 1m22.6 s, udp a cached pass of the same binary, run 1m6.1 s on b3e2e8d3); make lab-gotest PKG=./lab RUN='^TestCensorMatrix$/^(udp|reality)' ok in 214.7 s, all five labs PASS, reality × active prober NOT JUDGED (the upstream tell's baseline too short to attribute; reported, not a gate check). The same runs passed on b3e2e8d3 before the merge (matrix 257.4 s, same NOT JUDGED cell)
- 2026-11-22 not verified by a dedicated test: the session side in a real worker process (the ack timer's kill, a worker restarting mid-update, attach after a resend); the supervisor's lab tests with real workers (TestTwoSpacesShareAListener, TestRealitySpacesShareAListener, TestDeafWorkerHoldsNothingUp) and the matrix rows pass through it. No full make lab-test (brief: targeted runs only; the orchestrator runs full labs on rewrite)
- 2026-11-22 in-progress → review
- 2026-11-22 rewrite fa427ca0 merged (4eb8f029), runs again on it: make lint 0 issues, make test pass; lab-gotest supervisor/reality/udp ok, none cached (56 s, 1m24.5 s, 1m6.3 s); matrix udp and reality rows ok in 258.8 s, five labs PASS, reality × active prober NOT JUDGED as before
