---
id: TP-110
title: "Agent: the connection as a state type with events"
milestone: M2
area: agent
repo: thinkpol-vpn
size: M
depends_on: [TP-075]
split_from: TP-083
refs: [S1, DESIGN#desktop-client]
owner: "agent-claude"
branch: "tp-110-agent-connection-state-with-events"
---

## Goal
The device's connection lifecycle is one explicit state with transition methods and typed node events, replacing flag combinations and duplicate mode fields.

## Scope
- Explicit connection state (disconnected, connecting, connected, removed, retrying) with transition methods, replacing the flag combinations in the runner's connect/retry/next (`internal/agent/dataplane.go` ~447-640).
- One source of truth for mode (`n.mode` vs `n.report.mode` today).
- Typed node events (removed from space, back in space, connected, DNS unprotected, route table not enforced) emitted by the runner and engine; fewer `report.set` call sites.
- Invariants live in the transition methods; invalid transitions return errors and are tested.

## Out of scope
- Repositories, transaction manager or other persistence machinery for one state file.
- Engine struct split along field blocks: TP-083.
- Data-plane port types in the core: TP-109.

## Acceptance
- [x] behaviour unchanged: `make lint`, `make test`, `make lab-test` green
- [x] invalid connection transitions are errors with tests
- [x] node events are typed and emitted from runner/engine (not log strings only)

## Notes
- **Owner decision (2026-10-18):** explicit entity modelling without kernel persistence machinery; see PRD "Agent modelling (2026-10-18)".
- TP-041 (telemetry) consumes these events; TP-083's log-scraping replacement builds on them.
- **Where it lives (2026-10-19, round 2):** `internal/agent/connection.go` (the state and its methods, each guarding its own from-states; a refused move is `errInvalidTransition`, counted in `refused` and logged at error level by `logRefused`, the state unchanged); `internal/agent/events.go` (`Event`, `EventKind` with each kind's semantics, `Node.Subscribe`). The node owns the connection: `awaitSection` moves it while removed, the runner after; a server's worker runs a connection always meant to be up. Every way a device's node returns disconnects it (round 3: a stop, a stop during the first start, a failed first start, a stop while it waits out of its space; round 2 covered only a stop after the first start), so a returned node reads disconnected; the next start reads `Config.Connect`.
- **Events are told after the status shows them:** the runner queues the kinds and tells them at the end of `publish`, in the order queued; `mapFollower.take` returns removals and returns, and its callers (runner, `awaitSection`, `serverSpaces.run`) tell them after their report. Subscribers run on the node's goroutine; a panic in one is recovered and logged.
- **Problem events come from what the status shows (round 3):** at each `publish` the runner tells DNS unprotected and route table not enforced when the status starts showing them (`Status.DNSUnprotected`, `DataPlane.RouteTable.Error`), so a route table that recovers on its own and fails again is told again, and its own failed reapply and a resolver configuration that turns unprotected are told at the next publish (round 2 told them from the engine's errors only). `growRoutes` still wraps its failure with `dataplane.ErrRouteTableNotEnforced`, whose text is the old prefix.
- **`report.retrying` stays:** it is not `connRetrying` alone, it also covers a connected device's failed Apply and a server's failed map, both shown as `Status.Retrying`.
- **Not events yet (for TP-083/TP-041):** a problem that appears and clears between two publishes (the runner publishes when something wakes it: a map, a request, a retry, a listener, the 30 s status tick), so the route table's own reapply or a resolver configuration turning unprotected is told late or not at all; the leak guard failing; `SetDirectUpstreams` failing; there is no disconnected or retrying event kind.

## Review findings
- [x] R1.1 Drop the engine events port (internal/dataplane/events.go, EngineConfig.Events, pending/note/flushEvents and the deferred flushes); growRoutes' error is wrapped with a typed dataplane.ErrRouteTableNotEnforced, and the runner says EventRouteTableNotEnforced for a running engine only (apply's error, reloadRules, SetRules in the rules request), never from start(); the background reapply stays TP-083's note.
- [x] R1.2 Events go out only after the report shows them: the runner queues kinds and tells them at the end of publish() with the current map version; mapFollower.take returns what happened (removed now, back) instead of emitting, and its three callers tell removed/back after they publish; EventDNSUnprotected during a start comes after EventConnected; a test reads Status inside the callback for connected, removed, back and DNS unprotected.
- [x] R1.3 No transition table, move() or failTo: each method guards its own from-states with one switch; startFailed(retry bool); TestConnectionTransitions goes, TestConnectionLifecycle covers every method from every state.
- [x] R1.4 Names: one shared logRefused(log, err) (runner and awaitSection); conn.down() → disconnected(); conn.start() → resume(); runner.connected() inlined or named for what it does.
- [x] R1.5 Status from one source: Connected iff the connection is connected, Connecting for any other non-disconnected state, Serving for server mode; the engine only for the details; report.retrying dropped if it duplicates connRetrying; shutdown is a real transition in RunDataPlane (disconnect, then stop); existing status, CLI, local API and lab tests pass unchanged.
- [x] R1.6 Event semantics: removed and back are edges; DNS unprotected and route table not enforced are told when the problem goes from clear to set, not on every failed attempt; each kind's semantics documented on its constant.
- [x] R1.7 Comments: the worker's connection is "always meant to be up" (dataplane.go, Notes); DESIGN.md loses "the log lines say the same as before" and describes R1.1 and R1.2.
- [x] R1.8 Tests catch refused moves without log grepping (a refused count on the connection, asserted 0 after the run returns in startDevice and the runner tests); heardEvents.are fails on an extra or duplicate event after the expected list.
- [x] R1.9 Subscribers run on the node's goroutine (documented, must return quickly); a panicking subscriber is recovered and logged at error level, so it can't kill the node.
- [x] R1.10 runner.connect: a refused connection.connect has no side effects: it returns after logRefused, without starting the data plane.

- [x] R2.1 The route-table event is re-armed when the enforcer recovers on its own: both edges (route table, DNS unprotected) come from what the report shows at publish(), told when the problem goes from clear to set; a test with a table whose Status recovers on its own and fails again hears two events.
- [x] R2.2 The connection doesn't read connecting after the node returned: ctx ending during the first start and the first start failing are startFailed(false) then publish; ctx ending in awaitSection is disconnect; each tested; method guards fixed rather than refusals counted.
- [x] R2.3 publish tells events in the order queued (no Sort/Compact), so a double tell shows as a bug; events.go loses "in the order below".
- [x] R2.4 awaitSection answers a refused request with the error (logRefused, then req.done <- err).
- [x] R2.5 ErrRouteTableNotEnforced: its doc says why its text is "dataplane: route table" (existing messages unchanged).
- [x] R2.6 TestTheStatusShowsWhatAnEventSays waits until all five events were heard before checking.
- [x] R2.7 A test counts refusals on a worker's own connection (dp.conn nil).
- [x] R2.8 Ticket Notes and Log qualify what changed if R2.2 changes the claim.

## Log
- 2026-10-18 created in backlog (split from TP-083, owner decision)
- 2026-10-19 backlog → in-progress — owner: agent-claude, branch: tp-110-agent-connection-state-with-events
- 2026-10-19 the device's connection is one state (disconnected, connecting, connected, removed, retrying) with transition methods; it replaces the runner's down flag and the node's want; invalid moves are errInvalidTransition, tested over every from/to pair (TestConnectionTransitions) and per event (TestConnectionLifecycle); device and runner tests fail on a refused move in the log
- 2026-10-19 the mode lives in the report alone (Node.Mode reads it); report.set call sites in node.go, dataplane.go and resolver.go down from 11 to 8
- 2026-10-19 typed node events (Node.Subscribe): connected, removed from space, back in space (the map follower, all three paths), DNS unprotected (runner), route table not enforced (engine, EngineConfig.Events, told unlocked); log lines unchanged; tests assert the events heard
- 2026-10-19 docs: DESIGN.md "Engine and agent" describes the connection state and the node's events
- 2026-10-19 merged origin/rewrite: nothing new since the branch was cut
- 2026-10-19 make lint (exit 0) and make test (exit 0) at c8e972c; make lab-test exit 0 at c8e972c (lab suite ok, 35 node packages PASS), 484 s with LAB_P=1 (another lab was running). Not verified here: the route-table and DNS events on a real macOS device (needs a device run)
- 2026-10-19 in-progress → review
- 2026-10-19 review → has-errors — review round 1: R1.1–R1.9
- 2026-10-19 has-errors → in-progress — review round 1 findings picked up (R1.1–R1.9)
- 2026-10-19 review round 1 addendum: R1.10
- 2026-10-19 round 1: no engine events port (EngineConfig.Events and internal/dataplane/events.go gone); growRoutes' error is dataplane.ErrRouteTableNotEnforced, told by the runner for a running engine only (apply, SetRules, ReloadRules), never from a start
- 2026-10-19 round 1: events are told after the report shows them (queued, told at the end of publish in EventKind order; the map follower returns removals and returns, its three callers tell them after their report); DNS unprotected and route table not enforced are edges; TestTheStatusShowsWhatAnEventSays reads Status in the callback; a panicking subscriber is recovered and logged (TestAPanickingSubscriberDoesNotStopTheNode)
- 2026-10-19 round 1: the connection's methods guard their own states (no table, no failTo; startFailed(retry)); TestConnectionLifecycle covers every method from every state; refusals are counted on the connection and asserted 0 after the run returns; a refused connect or disconnect does nothing else; names logRefused, disconnected, resume
- 2026-10-19 round 1: Status.Connection comes from the connection alone and the node stopping disconnects it (a stopped node reads disconnected); report.retrying stays (it also covers a connected device's Apply and a server's map); the pre-existing status, CLI, local API and lab tests pass with their assertions unchanged (TestUnprotectedDNSIsReportedAndRetried now fails its first two pointings, to check the edge)
- 2026-10-19 docs: DESIGN.md "Engine and agent": events told once the status shows them, as edges, the route table's from ErrRouteTableNotEnforced
- 2026-10-19 merged origin/rewrite: nothing new (TP-109 not merged yet)
- 2026-10-19 make lint (exit 0) and make test (exit 0) at 1c9c182; make lab-test exit 0 at 1c9c182 (lab suite ok, 35 node packages PASS), 153 s with LAB_P=4 (no other lab running). Not verified here: the route-table and DNS events on a real macOS device
- 2026-10-19 in-progress → review
- 2026-10-19 review → has-errors — review round 2: R2.1–R2.8
- 2026-10-19 has-errors → in-progress — review round 2 findings picked up (R2.1–R2.8)
- 2026-10-19 merged origin/rewrite (TP-109): the engine's ports are its own types; the runner's routes go with its engine; ErrRouteTableNotEnforced still wraps growRoutes' failure, its doc says its text is the old prefix
- 2026-10-19 round 2: DNS unprotected and route table not enforced are told when the published status starts showing them, no flags of their own (TestARouteTableNotEnforcedIsToldAgainAfterItRecovered: a table that recovers on its own and fails again, two events; the DNS test hears a configuration turning unprotected at the next map); queued events are told in their order
- 2026-10-19 round 2: a returned node reads disconnected, which round 1's Log claimed for a stop only: a failed first start and a stop during it are startFailed(false), a stop while out of the space is disconnect (TestAStoppedNodeReadsDisconnected, TestAShutdownDuringTheFirstApplyIsNoFailure, TestAFailedStartClearsACrashedRunsRouteTable); awaitSection answers a refused request with the error; the runner tests run a worker's own connection (dp.conn nil) and assert it refused nothing; TestTheStatusShowsWhatAnEventSays waits for all five events
- 2026-10-19 docs: DESIGN.md "Engine and agent": problem events as the status shows them; a returned device reads disconnected
- 2026-10-19 make lint (exit 0) and make test (exit 0) at b47a0e8; make lab-test exit 0 at b47a0e8 (lab suite ok, 35 node packages PASS), 129 s with LAB_P=4 (no other lab running). Not verified here: the route-table and DNS events on a real macOS device
- 2026-10-19 in-progress → review
