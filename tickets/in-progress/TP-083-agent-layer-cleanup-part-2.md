---
id: TP-083
title: "Agent layer cleanup, part 2"
milestone: M2
area: agent
repo: thinkpol-vpn
size: L
depends_on: [TP-075, TP-109, TP-110]
split_from: TP-075
refs: [S1, DESIGN#desktop-client]
owner: "agent-tp-083"
branch: "tp-083-agent-layer-cleanup-part-2"
---

## Goal
Finish the agent-layer refactor after TP-075, TP-109 and TP-110: teardown order, transport wiring split, typed status and tests that don't scrape logs.

## Scope
- One LIFO cleanup stack owned by the engine (teardown order today depends on where `defer` sits; three hand-written unwind paths in `runner.start`).
- Split `transport.Router` and `ListenConfig`.
- One typed status vocabulary (today mixes snake_case codes, lowercase step words and English sentences; `EgressInfo.Err` is raw `err.Error()`).
- Status-based test synchronisation instead of `waitLog` on log text (~twenty agent tests), driven by TP-110's node events.
- Split `Engine` along the invariants each block protects (`internal/dataplane/engine.go` ~121-194): one owner for "a peer key lives on one device", one for "direct routes shrink before the router table changes and grow after".
- One table each for counters (`internal/agent/localapi/convert.go` ~61-81 with `render.go` ~176), refusals (`errors.go` ~18-32, `client.go` ~191-201) and display names (`enumName`).
- Move `cmd/thinkpol/dev_lists_build.go` logic (~41-83) out of `cmd/`.
- Deduplicate the six command files' shared socket flag and dial prologue.
- The remaining private test hooks on `DataPlane` and `Node` (path, retryAfter, blobOptions, onEngine, dnsPort, `Node.tweak`): where they stay, say so in one place; where a typed status (this ticket) can replace them, drop them.

## Out of scope
- Data-plane port types and depguard on core imports: TP-109.
- Connection state type and node events: TP-110.
- New product features; Windows/Android adapters (TP-047).

## Acceptance
- [x] behaviour unchanged: `make lint`, `make test`, `make lab-test` green
- [x] the depguard rule from TP-109 stays green
- [x] no `waitLog` on log text left in `internal/agent` tests (one exception: `localapi`'s `TestAnAPIFailureLeavesTheNodeRunning` waits for the local API adapter's retry warnings, which only the log reports)
- [x] `funlen` on in `.golangci.yml` (lines ~80, statements ~50), the long functions split by what their parts do

Round 2 (2026-10-22): correctness (merge), design (fix first), second opinion (fix first; its finding, a refused table leaving a staying device's moved peer off WireGuard, is refuted: the retry's `remove` returns early and `add` restores it once the router accepts a table, and until then the peer is dropped, not leaked, as before).
- [x] R2.1 The later-upstreams log wait (`server_test.go` ~465-484) isn't justified: the behaviour is observable, and `TestTheResolverAsksTheLatestUpstreams` already proves the runner side by real queries. What the subtest adds is the worker-side forwarding. Move the `forward` closure (`servespace.go` ~56-68) into a small named type (e.g. `upstreamChanges` with `offer(WorkerConfig)`) and unit-test it: the first config's list sends nothing, a changed list sends once, the same list again sends nothing. Drop the log wait (keep the subtest only for what it checks otherwise), and the waitLog box names localapi's as the only exception again.
- [x] R2.2 New in this branch: `mapFollower.take` counts a map that is merely not newer as refused (`mapfollower.go` ~43-46), so a SIGHUP or a `touch` of an unchanged map file makes `thinkpol status` say "maps refused: 1 … (the service's log says why)" while the log says nothing above debug. Count only maps that are invalid or not for this node; a test that a repeated map leaves the count at 0.
- [x] R2.3 Nits: Log line on unknown enums is wrong (protobuf's `String()` gives the number; say what the CLI printed before and prints now); `resolver.go` ~38 reads "no DeviceHost" as "upstreams came from the worker's config": name it once (`func (dp *DataPlane) inWorker() bool`, with the reason) and use it only there, or say on `Forward` that the two go together; `routetable.Problem` with `Error*` constants in `Error`/`GuardError` fields is three names for one thing and a second `Problem` beside `agent.Problem`: rename it `routetable.ErrorCode`; `dataplane.GuardFailed`/`GuardUnsupported` → `RouteTableGuardFailed`/`RouteTableGuardUnsupported`; `blobListeners` holds the whole `*Service` but needs the listen retry, the log and `openListener`, and the deferred teardown in `serve.go` ~39-41 still loops over `ls.open`: give it `closeAll()`; `DataPlane.Host` is a `WorkerHost` next to `agent.Host` (worker plus device): rename the field `Namespace`; Notes still name `DataPlane.inWorker`; R1.1's worker test doesn't hook `SetSystemDNS`: make the test host's setter fail the test if a worker calls it.

## Notes
- **Split (backlog grooming 2026-10-15):** split from TP-075; part 1 (composition root and map follower) must land first for TP-046.
- **Independent review (2026-10-15), file:line evidence (part 2 slice):** three DI styles on `DataPlane` (ten private hook fields, package-level swappable vars, `tweak func`); Linux-shaped ports (`netcfg.Rule` with `Oif`, `Mark`, `SuppressDefaultRoutes`; `routetable.Config` without build tags); `dataplane/routetable.go:17-21` declared in terms of `routetable.Want`; `engine.go:103` imports `dns`, which justified the depguard rule (now TP-109); status vocabulary not fixed; ~twenty tests use `waitLog("map applied")` though `Status().MapVersion` exposes the fact.
- **Host in the worker (TP-075 review round 3):** `agent.Host` carries device-only adapters (the route table and its leak guard, clearing a crashed run's routes, the OS's resolvers and their configuration) into the sandboxed worker too; only the `DataPlane.Forward` and `DataPlane.RouteTable` flags keep the worker off them (and, for the OS resolver configuration, its section's kind). A narrower worker port, or a check that refuses them, belongs with the port split here. Done in round 1 (R1.1): a worker's data plane has a `WorkerHost` and no `DeviceHost`; TP-112's `DataPlane.inWorker` field went in the merge, `DataPlane.inWorker()` now reads "no Device".

## Review findings
Round 1 (2026-10-21): correctness (fix first), design (fix first), second opinion (merge).
- [x] R1.1 Proven: a server's worker panics on a nil `Host.SetSystemDNS` when its section's kind is device (`-mode server` on a device section, or a newer map turning a running server's kind to device): `pointSystem` is gated only on the resolver and the kind, and `workerHost` leaves the adapter nil, so the worker crash-loops. Make it impossible by type: a `WorkerHost` with what a worker uses (configurator, TUN, transports, BlobNet), `Host` embedding it plus the device-only adapters, and `ServeSpace` taking a `WorkerHost`; the "inside a worker" paths (`pointSystem`/`systemConfig`) never reach device adapters. Test through `serveSpace` with a device-kind section; fix the `Host` doc ("Required" on `NewGuard`).
- [x] R1.2 `last_exit` contradicts DESIGN.md (~177: workers are shown without their exit messages) and is the last raw error text on the wire. DESIGN wins: send a typed code (e.g. `spawn_failed`, `config_timeout`, `killed`, `exited`), keep the text in `supervisor.WorkerInfo.LastExit` for logs and the lab tests, map in `convert.go`.
- [x] R1.3 Untyped codes left: the route table's `Error`/`GuardError` and their constants are bare strings, documented as "fixed texts" (`routetable/routetable.go` ~313-357, `dataplane/routetable.go` ~47-57); every `Problem*` in `agent/status.go` is a bare string. Type them (`dataplane.RouteTableError` mapped in `engineports.go`, `agent.Problem`) and fix the comments. `ipv6OffCodes[e.ipv6Off]` gives "" for an error it doesn't know: `errors.Is` with a default code.
- [x] R1.4 `Status.MapsRefused` is read only by a test. Owner's call pending; default: put it on the wire (a counter in `dataPlaneCounters` and a render line: an operator wants to know when a node keeps refusing maps).
- [x] R1.5 "the one place a data plane differs in tests" is false: `Node.tweak` sets `dp.RouteTable = false` (production always true) and can rewrite any field, `Host` included. Replace `tweak` with `tuning` on `Node`; give the test platform a no-op route table so device tests run with `RouteTable: true` as production does.
- [x] R1.6 TP-102 is merged into `rewrite`: merge it here, drop the two `funlen` exclusions in `.golangci.yml` (netcfg `apply`, dns `answer` — split them if TP-102 left them over the limits), and keep the gate green.
- [x] R1.7 `transport.Accept` (a type) shares its name with `Listener.Accept` (the interface's method), and `memory.go` has an `accept` parameter next to an `accept` field: rename (e.g. `Admission`). `StreamRoutable.Handoff` lost the listener's settings that a TLS handoff (TP-028) will need: pass them, or say in the port's doc where they come from.
- [x] R1.8 `deviceSet.remove` (`devices.go` ~87) deletes departing devices from `byName` and returns without closing them when `setTable` fails: a still-bound device owns its peer and the next `add` hits `ErrPeerTaken`. Close (or keep tracking) on that path; `engine.table()`/`Status()` reach into `e.devices.byName`: give deviceSet an iterator.
- [x] R1.9 Tests: `TestDirectRoutesShrinkBeforeTheRouterChangesAndGrowAfter` never reads the `RouteTableWant` installed while each Enforce is held — assert the shrunk want is in place before the router changes; `TestAWorkerGetsNoDeviceAdapter` checks fields, not behaviour (R1.1's test replaces it); `dataplane_test.go` ~599 lets a TUN close twice (exact counts); the ticked waitLog box names `localapi`'s remaining log wait as the one exception.
- [x] R1.10 Nits: `undo = undoStack{engine.Close}` drops what `openPorts` pushed — open the resolver in `start` after `openPorts` so `openPorts` pushes only what `NewEngine` takes over, and say so; `blobs/serve.go` `pruneListeners`/`openListeners` pass the same state around: a `blobListeners` type; `status.go` ~136 comment lists Step codes without `StepEngine`; `lists.WriteReport` (a CLI table) out of the packet-path package (e.g. into `devmap` or a `listsbuild` package); `split.go` computes `w.Direct.Minus(l.overlaySet)` twice; `localapi.proto` step and `ipv6_off` comments; the Log names every visible output change (also: an unknown enum value prints `unknown` instead of its number) and the start-failure close order now strictly LIFO.

## Log
- 2026-10-15 created in backlog (split from TP-075, backlog grooming)
- 2026-10-15 docs (backlog grooming, review fixes): recovered part-2 evidence note from original TP-075
- 2026-10-18 split: port ownership → TP-109, connection state and events → TP-110; Engine split and local API tables added (owner)
- 2026-10-19 docs (TP-075 review round 2): the remaining private test hooks on DataPlane and Node (path, retryAfter, onEngine, dnsPort, tweak) are this ticket's scope
- 2026-10-19 docs (TP-075 review round 3): blobOptions joins the private test hooks; note that Host reaches the worker kept off its device-only adapters only by the Forward and RouteTable flags
- 2026-10-21 backlog → in-progress — owner: agent-tp-083, branch: tp-083-agent-layer-cleanup-part-2
- 2026-10-21 scope: the funlen gate is this ticket's (ORCHESTRATION "Consolidation phase": whichever of TP-083 and TP-102 lands last adds it, assumed TP-083); acceptance box added
- 2026-10-21 waitLog (54a5e43): internal/agent tests wait for Status (MapVersion with Retrying and the last Apply, Removed, Listeners, the new MapsRefused) and the node events instead of log lines; runningNode and serverSpaces tests get a report to read; Status.MapsRefused (maps given and not taken: not newer, invalid, not the space's) is new, kept off the local API's wire for now
- 2026-10-21 waitLog, changed tests: a stopped listener syncs on its reopen; the worker's seeded blob on the device holding it; a panicking subscriber on a second subscriber after it, then asserts the logged panic; the DNS first-read warnings are asserted without waiting (logged before what the test waits for); left: plain log assertions where logging is the behaviour (said once, the map applied line's attributes), and localapi's TestAnAPIFailureLeavesTheNodeRunning, which waits for the adapter's retry warnings because nothing reports them but the log
- 2026-10-21 LIFO cleanup (e2b3464): runner.start pushes each Close onto one undoStack (openPorts), a failure runs it last first, the engine's Close replaces what it owns; stop keeps its explicit order (listeners close before the engine and are waited for after it), so it isn't a LIFO of set-up; RunDataPlane's deferred teardown order is unchanged; "owned by the engine" read as owned by the data plane's start
- 2026-10-21 Engine split (a204d82): deviceSet (devices.go) keeps a peer key on one device; osRoutes.around (routetable.go) shrinks direct routes before the router table changes and grows them after, for Apply and rule changes alike; new test holds each Enforce and checks the router meanwhile
- 2026-10-21 Router/ListenConfig (c7f49d8): ListenConfig{Address, Settings} and Accept{Peers, Camouflage}; PacketRouter and StreamRouter replace Router (udp no longer answers RouteStream), Routable goes
- 2026-10-21 status vocabulary (1b27684): dataplane.Step typed ("route table" is "route_table", also in start_failed:<step>), IPv6Off and the route table's Error/GuardError are codes, supervisor.EgressInfo.Err an EgressError code instead of err.Error(); left: WorkerStatus.LastExit stays the process's error text (its lab tests read it); note: DESIGN.md "Local API" says workers are shown without their exit messages, but last_exit carries them since 66d3f31 (TP-068), not changed here
- 2026-10-21 localapi tables (6dfbf3d): dataPlaneCounters (name, kind, reader) feeds convert and render; refusals holds each refusal's gRPC code and message; displayNames replaces enumName
- 2026-10-21 dev lists build (c738e72): lists.BuildFile and lists.WriteReport; the command parses flags and calls them
- 2026-10-21 socket flag and dial prologue (287c6b4): newAPICommand(name).dial in cli.go, used by the six local API commands
- 2026-10-21 test hooks (43b98e1): onEngine dropped (its test reads the status); path, retryAfter, blobOptions and dnsPort are one tuning struct, documented as the one place a data plane differs in tests; Node.tweak stays as how a node's data plane gets it
- 2026-10-21 Host in the worker (1d9525a, the Notes' item): ServeSpace hands the worker workerHost(h), without the device-only adapters
- 2026-10-21 funlen (a82d4df, bf89206, b7a6d06, e06538e, 1fe8183, bf80b89): lines 80, statements 50, comments not counted, tests exempt; the tightest round limits met (70 lines would fail transporttest's pingPong, 45 statements devmap's spec and three more); no nolint; two config exclusions for functions TP-102 rewrites (netcfg's apply on Linux and macOS, dns's answer), to drop when TP-102 merges; blobs, rules/dns/firewall and netmap/devmap splits drafted by subagents, reviewed here
- 2026-10-21 not verified here: the macOS code touched (routetable splitRoutes and watch, dns dynamicStore.apply, netcfg Validate) by unit tests only; the phase's macOS device checklist covers it
- 2026-10-21 checks at bf80b89: make lint and make test green; make lab-test green (LAB_P=4, 4m05s)
- 2026-10-21 in-progress → review
- 2026-10-21 review → has-errors (round 1: R1.1–R1.10)
- 2026-10-21 has-errors → in-progress (round 1 findings)
- 2026-10-21 round 1, R1.6: merged origin/rewrite with TP-102 (9f6df14; no conflicts: its splits and this branch's touch different hunks), funlen exclusions dropped (71a4485)
- 2026-10-21 round 1, R1.1 (ccb7e2e): Host is WorkerHost plus DeviceHost; DataPlane takes Host WorkerHost and Device *DeviceHost; ServeSpace takes a WorkerHost and a worker's data plane never has a Device; the test through serveSpace with a device's section panicked before the fix
- 2026-10-21 round 1, R1.2 (6a1a012, aaf2ed1): supervisor.ExitReason codes (spawn_failed, not_ready, unresponsive, protocol_error, killed, exited) on the wire as last_exit; WorkerInfo.LastExit keeps the text for the log and the lab tests; 6a1a012 was pushed with a status test failing (its gate didn't stop the commit), fixed in aaf2ed1
- 2026-10-21 round 1, R1.3 (50ad9e4): routetable.Problem, dataplane.RouteTableError (mapped in engineports.go; one the map doesn't know is apply_failed, never none), agent.Problem; IPv6 off by errors.Is with "other" as the default
- 2026-10-21 round 1, R1.4 (283919e): maps_refused on the wire as a top-level Status field, with a CLI line, not a data plane counter: a server and a device out of its space follow maps with no data plane in their status
- 2026-10-21 round 1, R1.5 (a0a30ff): Node.tuning replaces Node.tweak; the test platform's route table takes every Want and changes nothing, so device tests run with RouteTable on
- 2026-10-21 round 1, R1.7 (13c36ae): transport.Admission; Handoff's doc says the settings stay with the supervisor's public listener, a worker's shared listener doesn't carry them (it never did), and tls (TP-028) adds them there
- 2026-10-21 round 1, R1.8 (a6df885): departing devices go back into the set when the router refuses the table; deviceSet.all/get/len; the new test hit ErrPeerTaken before the fix
- 2026-10-21 round 1, R1.9 (6529fee): the ordering test reads the held Want; exact TUN close count; the waitLog box names its exceptions (also TP-112's later-upstreams subtest after the merge, 8a0bd5d)
- 2026-10-21 round 1, R1.10 (646b4c9): resolver opened in start after openPorts; blobListeners; StartError doc; splitRoutes' direct set once; devmap.WriteListsReport; proto comments in 6a1a012
- 2026-10-21 visible output changes on this branch: the Apply step "route table" is "route_table" (also in start_failed:<step>); ipv6_off, the uplink's error and last_exit are codes instead of text; health problems unchanged; a new maps refused line and maps_refused field; an enum value the CLI doesn't know prints "unknown" instead of its lowercased identifier; a failed start's closes run strictly last first (the TUN before its configurator, the resolver first), none depending on another
- 2026-10-21 merged origin/rewrite with TP-112 (c17d93b): its DataPlane.inWorker is this branch's Device == nil and goes; its "map applied" waits use the status, its other log waits converted in 8a0bd5d but the later-upstreams one
- 2026-10-21 round 1 checks at 8a0bd5d: make lint and make test green; make lab-test green (LAB_P=1, another checkout's lab running, 6m24s)
- 2026-10-21 in-progress → review
- 2026-10-22 review → has-errors (round 2: R2.1-R2.3)
- 2026-10-22 has-errors → in-progress (round 2 findings)
- 2026-10-22 merged origin/rewrite with TP-120 (77d47be), no conflicts
- 2026-10-22 round 2, R2.2 (128776e): only invalid maps and maps not the node's count as refused; test TestARepeatedMapIsNotARefusal (the same map, a tampered one, the next version: one refusal); counting not-newer maps again fails it with 2
- 2026-10-22 round 2, R2.1 (4c4d5f2): upstreamChanges.offer replaces the worker's forward closure; test TestUpstreamChangesPassOnlyChangedLists (first list again, a change, the same again, two changes); offering every list fails it; TestServeSpace's subtest no longer waits for a log line; the waitLog box names localapi's wait as the only exception
- 2026-10-22 round 2, R2.3 (9fafbf1): DataPlane.inWorker(), routetable.ErrorCode, RouteTableGuardFailed/RouteTableGuardUnsupported, blobListeners without the Service and with closeAll, DataPlane.Namespace, Notes; TestAWorkerOnADeviceSectionLeavesTheOSResolverAlone's device adapters fail the test if called, and keeping the base's Device in workerDataPlane fails it on SetSystemDNS
- 2026-10-22 correction to the 2026-10-21 line on visible output: for an enum value the CLI doesn't know, `thinkpol status` printed the value's number (protobuf's String() of an unknown value, lowercased by enumName), and prints "unknown" now
- 2026-10-22 round 2 checks at 9fafbf1: make lint and make test green; make lab-test green (LAB_P=4, 3m12s)
