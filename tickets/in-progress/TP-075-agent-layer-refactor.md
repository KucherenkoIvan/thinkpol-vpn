---
id: TP-075
title: "Agent layer cleanup, part 1"
milestone: M2
area: agent
repo: thinkpol-vpn
size: M
depends_on: [TP-019]
refs: [S1, DESIGN#desktop-client]
owner: "agent-glm"
branch: "tp-075-agent-layer-refactor"
---

## Goal
`internal/agent` has one composition root and one map follower so TP-046 can install the service without copying control flow per OS.

## Scope
- A `Platform` struct built in `cmd/` (adapters today are built in `node.go:239`, `dataplane.go:191-211`, `supervisor_linux.go:92`; `cmd/thinkpol/up.go` calls `agent.Prepare` then `node.Adapters(reload)` and optionally appends the local API adapter).
- One `mapFollower` replacing the three copies (`Node.awaitSection`, `serverSpaces.next`, `runner.next`).

## Out of scope
- Status vocabulary, `waitLog` test synchronisation, transport `Router`/`ListenConfig` split, LIFO cleanup stack and depguard on dataplane imports: TP-083.
- New product features; Windows/Android adapters: TP-047 (after this ticket).

## Acceptance
- [x] behaviour unchanged for map follow and adapter wiring: `make lint`, `make test`, `make lab-test` green
- [x] one `mapFollower` with a single `take(envelope)` used from device and server modes

## Notes
- **Split (backlog grooming 2026-10-15):** this ticket is part 1 only. TP-083 takes the rest of the original TP-075 refactor (status vocabulary, `waitLog` removal, cleanup stack, transport split, depguard).
- **Independent review (2026-10-15), file:line evidence (composition root and map follower):** adapters built in `node.go:239`, `dataplane.go:191-211`, `supervisor_linux.go:92` vs `cmd/thinkpol/up.go` (`Prepare`, `Adapters`); map-follow state three times with the same log strings.
- **One `follower.take` (from TP-037 / TP-011):** device mode (`runner.next` in `dataplane.go`) and server mode (`serverSpaces.next` in `node.go`) each run `(*Map).Next` → `openSection` → removed/back-in-space logic. Fold them into one `follower` (current map, section, removed flag) with a single `take(envelope)` both modes call, so the semantics can't drift.
- This is also the architecture correction: the composition root moves from `internal/agent` to `cmd/`, so the data plane's adapters are built and passed in, not built by the core.

## Review findings
- [x] R2.1 DESIGN.md (~301, "Engine and agent"): the node's host adapters (TUN and its configurator, the route table with the host's leak guard, the resolver configuration, the host lock) are built by the composition root (cmd/thinkpol) per OS and handed to internal/agent; the agent sequences them and never constructs them. Log line saying DESIGN changed.
- [x] R2.2 Split Platform by who may use it: agent.Host = what one data plane needs of its network stack (NewConfigurator, NewTUN, NewGuard, NewRouteTable, ClearConfig, ClearRouteTable, SetSystemDNS, SystemUpstreams, BlobNet blobs.Net — zero value = real sockets); agent.Platform = Host + host-wide LockHost, RestoreDNS. DataPlane carries Host only; ServeSpace(log, Host); worker.go passes platform().Host. The sandboxed worker must not receive LockHost or a supervisor factory.
- [x] R2.3 cmd/thinkpol/platform.go is wiring only: every field a reference to an existing function (one type shim for NewRouteTable allowed). The TUN ordering/rollback and the MTU (const tunMTU = 1420) move into runner.start; the owner dispatch of clearing moves into Host (clearNetwork: ClearRouteTable(NewGuard()), then ClearConfig(OwnerOverlay)); keep routetable.New's argument order (guard, log).
- [x] R2.4 Drop Platform.NewSupervisor: node.go calls supervisor.New with NewRoot from n.plat.NewConfigurator(netcfg.OwnerSupervisor); remove supervisor_linux.go's NewRoot default (unset NewRoot is an error) and its caller-describing comment.
- [x] R2.5 The transport registry and the device's blob service: build the udp adapter's socket control via Host (e.g. Host.Transports, or the SocketControl as a Host field) and the blob service with blobs.NewOnNet(o, h.BlobNet) — or, if moving Transports is too large, write the deferral into the ticket Notes and DESIGN explicitly; do not leave the Log claiming the correction is complete. Remove the base.Registry == nil test-only fallback in servespace.go if Transports moves. Replace TP-104's newBlobs field hook: BlobNet in Host is the seam; the fastBlobs Limits override stays a private test hook.
- [x] R2.6 mapFollower is a named field (follow mapFollower), not embedded; serverSpaces gets its own log; one markRemoved(m) owns the removal warning (awaitSection uses it instead of logging itself); drop warnKind (Node.Kind 0 already means no kind).
- [x] R2.7 Put mode back on awaitSection's "back in space" line (log it after resolveMode, with "mode", n.mode), and after the dropped-connect warning, as before. Test that asserts mode= on that line.
- [x] R2.8 Tests inject only through Prepare's Platform (no n.tweak overwriting dp.Platform after Prepare); server_test.go checks the removedMsg the code actually uses (not a copy).
- [x] R2.9 hostlock_unix.go: one doc comment (no stacked old paragraph, no "who wires it").
- [x] R2.10 The ticket's hook attribution: the remaining private test fields (path, retryAfter, onEngine, dnsPort, Node.tweak) — add a Scope bullet to TP-083 (tickets/backlog/TP-083-*.md, with a Log line) or correct this ticket's Log; blobOptions/newBlobs is this ticket's now (R2.5).
- [x] R2.11 Nits: comments state constraints, not who calls (platform.go, node.go, dataplane.go, servespace.go, cmd platform.go, tests); validate the whole Platform/Host once in Prepare/ServeSpace or drop the partial nil check and its test-mentioning message; one name clearNetwork; rewrite Log line ~44: "Not verified here: the adapters' host-side paths outside the lab's Linux (macOS device on a real network: needs_human: macos)".
- [x] R3.1 One "back in space" line: a node that starts removed logs one line, with mode, after the dropped-connect warning (as before this ticket); runner and serverSpaces keep their own modeless line; test: strings.Count(out, "back in space") == 1 on the start-while-removed path, the line carries mode=, the warning comes first when a connect was requested.
- [x] R3.2 R2.8 was ticked but not done: tests still write Host fakes onto dp.Host from n.tweak after Prepare (status_test.go, resolver_test.go). Every Host/Platform fake goes into the Platform passed to Prepare (startDevice's opts get the *Platform before Prepare); n.tweak keeps only the private DataPlane fields (TP-083's). A Node.run that stopped copying plat.Host must fail a test.
- [x] R3.3 R2.1's Log line is missing: DESIGN.md "Engine and agent" changed.
- [x] R3.4 Comments state constraints, not callers: platform.go (Platform, Transports, BlobNet), servespace.go, node.go, supervisor/supervisor_linux.go, supervisor/options.go (NewRoot, "Zero values take the defaults"), rollback_linux_test.go.
- [x] R3.5 One name: runner.clearRoutes goes, the Host's clearNetwork logs its own warning; no duplicate "removing a previous run's routes failed" string.
- [x] R3.6 servespace.go: no conditional MaxHeld default (TP-104 set ServerMaxHeldSize directly); the test hook keeps the server's MaxHeld.
- [x] R3.7 A test pins markSockets per mode (device and supervisor true, worker false): the test helper's Transports records its argument.
- [x] R3.8 TP-083's ticket: its private-hooks list includes blobOptions; a Notes line that Host carries device-only adapters into the worker, kept off only by the Forward and RouteTable flags. Log line there.
- [x] R3.9 Nits: platform_test.go Transports closure → Transports; cmd/thinkpol/up.go applyPlatformDefaults moves into internal/agent (agent.ApplyOSDefaults) so cmd only calls it; optionally platform_{linux,darwin,other}.go → supported_*.go.
- [ ] R4.1 status_test.go: TestARemovedDeviceConnectsOnceBack and TestAStartWhileDisconnectedClearsACrashedRunsRoutes build their device on startDevice (deviceOpt.prepare writes the removed map into c.StateDir; the clear fakes go into p.ClearConfig / p.ClearRouteTable), not a third hand-built copy; same assertions.
- [ ] R4.2 TestARemovedDeviceConnectsOnceBack (through n.run on a removed start) asserts strings.Count(log, "back in space") == 1.
- [ ] R4.3 supervisor/options.go: Log and Output state the constraint, not their callers.
- [ ] R4.4 Why a worker doesn't mark its sockets is said once (transports.go); no repeats in servespace.go and node.go, no caller list in transports.go.
- [ ] R4.5 servespace.go: ServeSpace's doc says what it does, not who calls it; dataplane.go: no Host field comment restating the type; the private-fields comment says what tests tune.
- [ ] R4.6 platform.go NewGuard: the host's leak guard or nil where the host has none yet (Windows: TP-047/TP-048); required.
- [ ] R4.7 node.go awaitSection: no cur set then markRemoved on the same map; uses take's back result instead of reading f.removed.
- [ ] R4.8 deviceOpt.run → dataPlane; TestClearingTheNetworkTriesBothOwners in platform_test.go; blobs_test.go drops the unused r.
- [ ] R4.9 DESIGN.md "Engine and agent": adapters chosen and wired by the composition root per OS (HostLock and Transports live in internal/agent); TP-083 Notes without the stray blank line; the flaky transporttest ShapingRefused failure goes to TP-113's Notes.

## Log
- 2026-10-15 created in backlog
- 2026-10-15 docs: board fix-ups (log order, refs, parked notes)
- 2026-10-15 docs (backlog grooming): milestone M2; split — part 1 (composition root + map follower); TP-083 is part 2
- 2026-10-15 docs (backlog grooming, review fixes): cites and up.go wording; follower semantics from TP-037; Windows dep wording
- 2026-10-19 backlog → in-progress — owner: agent-glm, branch: tp-075-agent-layer-refactor
- 2026-10-19 the composition root (cmd/thinkpol's platform()) builds the node's host adapters and hands them to internal/agent as agent.Platform; the package-variable test hooks are gone, tests fake adapters through the same Platform (tweak/onEngine/private fields stay: TP-083)
- 2026-10-19 one mapFollower with a single take(envelope) for Node.awaitSection, serverSpaces and the data plane's runner (device and server modes); log line texts unchanged
- 2026-10-19 merged origin/rewrite (TP-107); TP-104 not merged yet, so no blobs.Net in the Platform
- 2026-10-19 in-progress → review — make lint, make test green; make lab-test green (exit 0, all 35 node packages PASS, lab suite ok) at c38c9d2. Not verified here: the adapters' host-side paths outside the lab's Linux (macOS device on a real network: needs_human: macos)
- 2026-10-19 review → has-errors — review round 2: R2.1–R2.11
- 2026-10-19 has-errors → in-progress — review round 2 findings picked up (R2.1–R2.11)
- 2026-10-19 merged origin/rewrite (TP-104): the data plane's Host replaces TP-104's newTUN/newRoutes/clearNetwork hooks; its newBlobs hook stayed only until BlobNet took it over
- 2026-10-19 round 2: Platform split by who may use it — agent.Host is what one data plane needs of its network stack (NewConfigurator, NewTUN, NewGuard, NewRouteTable, ClearConfig, ClearRouteTable, SetSystemDNS, SystemUpstreams, Transports, BlobNet), agent.Platform adds the host-wide LockHost and RestoreDNS; DataPlane carries Host, ServeSpace(log, Host), the sandboxed worker takes a Host only
- 2026-10-19 round 2: cmd/thinkpol's platform() is wiring only (every field a reference to an existing function, NewRouteTable its one type shim); the TUN ordering, rollback and MTU moved into runner.start; clearNetwork is one name on Host (ClearRouteTable(NewGuard()), then ClearConfig(OwnerOverlay)); the supervisor takes NewRoot from the node's Host, its own default is gone (unset is an error)
- 2026-10-19 round 2: the worker's blob service is blobs.NewOnNet(o, Host.BlobNet), the fastBlobs limits override stays a private hook (blobOptions); TP-104's newBlobs hook and serveSpace's test-only Registry fallback are gone, the worker builds its registry through Host.Transports
- 2026-10-19 round 2: one named map follower (follow) with markRemoved owning the removal warning; no warnKind (a kind held is the running node's, 0 is none); the node's back-in-space line carries its mode again; tests inject through Prepare's Platform; the private test hooks left (path, retryAfter, onEngine, dnsPort, tweak) are TP-083's scope
- 2026-10-19 in-progress → review — make lint, make test green; make lab-test green (exit 0, 35 packages PASS) at d1e40b0. Not verified here: the adapters' host-side paths outside the lab's Linux (macOS device on a real network: needs_human: macos)
- 2026-10-19 review → has-errors — review round 3: R3.1–R3.9
- 2026-10-19 has-errors → in-progress — review round 3 findings picked up (R3.1–R3.9)
- 2026-10-19 merged origin/rewrite (TP-103, TP-104, TP-108, TP-114): TP-108's upstreamsUnknown stays, its system resolver calls go through r.dp.Host (SystemUpstreams, SetSystemDNS); the supervisor's lab tests pass NewRoot next to TP-103's rebuild failer
- 2026-10-19 docs: DESIGN.md "Engine and agent": the node's host adapters are built by cmd/thinkpol per OS and handed to internal/agent (agent.Host for one data plane; agent.Platform adds the host-wide ones); the agent sequences them and never constructs them
- 2026-10-19 round 3: take reports a node back in its space and the caller says so (sayBack): runner and serverSpaces at once, without mode, as before; a node that started removed once, with its mode, after the dropped-connect warning; Host.clearNetwork logs its own warning (runner.clearRoutes gone)
- 2026-10-19 round 3: device tests put every host fake into the Platform passed to Prepare (startDevice's deviceOpt.prepare), n.tweak keeps only the private DataPlane fields; a test pins markSockets per mode (device and supervisor true, worker false); a worker's blob service always holds the server's MaxHeld
- 2026-10-19 round 3: comments state constraints, not callers (platform.go, servespace.go, node.go, supervisor options and New, rollback test); agent.ApplyOSDefaults replaces cmd's applyPlatformDefaults; platform_{linux,darwin,other}.go renamed supported_*.go; TP-083 lists blobOptions and notes the Host the worker carries
- 2026-10-19 in-progress → review — make lint, make test green; make lab-test green (exit 0, 35 packages PASS) at 1523831 (a first run hit a timing failure in transporttest ShapingRefused behind the supervisor; the package passed alone and the full rerun passed). Not verified here: the adapters' host-side paths outside the lab's Linux (macOS device on a real network: needs_human: macos)
- 2026-10-19 review → has-errors — review round 4: R4.1–R4.9
- 2026-10-19 has-errors → in-progress — review round 4 findings picked up (R4.1–R4.9)
- 2026-10-19 the flaky transporttest ShapingRefused run (round 3 lab-test) is noted in TP-113
