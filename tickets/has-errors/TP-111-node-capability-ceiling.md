---
id: TP-111
title: "`up`'s `-mode` defaults to `device`"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-046, TP-166]
refs: [A4, docs/design/overlay.md#node-agent]
owner: "agent-tp-111"
branch: "tp-111-mode-defaults-to-device"
stream: core
---

## Goal
A node starts as a device: it forwards nothing unless its node file allows it (PRD A4: a node starts with ingress and egress off). The map's node kind no longer picks how a node runs.

## Scope
- `up`'s `-mode` defaults to `device`: no forwarding unless the node file allows it. `auto` goes.
- The mode is read from the node file TP-166 builds (flags over env over the file over defaults); a bad value exits EX_CONFIG (78).
- Lab: tests that ran their exits under `auto` set server mode.

## Out of scope
- The capability-ceiling file mechanism (per-capability opt-in, the map checked against the ceiling at start and while running): TP-183 (after the MVP).
- Nodes advertising their ceiling to the controller, and the builder refusing to publish a map that asks for more: M4 (TP-034, TP-038).
- Devices as exits or as routers into a home network: after the MVP (docs/design/milestones.md, Out of scope).

## Acceptance
- [x] unit test: with no `-mode` and no node-file setting, `up` runs in device mode and forwards nothing
- [x] lab: a node whose map makes it an exit, started without the node file allowing server mode, carries no forwarded traffic
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- Owner decisions 2026-10-18: default `device`, opted into locally (Tailscale's model). The decisions on mismatches between the map and the ceiling are TP-183's.
- Found through TP-098's review: a server section run with `-mode device` had no upstreams and logged a false reason.
- **Slot (pre-M2 phase, 2026-10-24).** Wave 1, Agent lane: after TP-140. Starts only after the owner's TP-139 session, whose verdicts on its planned surface go into this ticket first. Keeps its 2026-10-18 decisions.
- **TP-139 verdicts (TP-139 owner session, 2026-11-07; docs/design/api-overview.md "Verdicts", docs/design/configuration.md).** The mode lives in the node file that TP-166 builds (root-owned, 0600), with flags over env over the file over defaults. Depends on TP-166. A bad value exits EX_CONFIG (78).
- Split 2026-11-07 (owner's MVP cut): the capability-ceiling file mechanism moved to TP-183. Until it lands, RR42 holds for a node run in server mode.

## Review findings
- [ ] R1.1 (blocker) device mode + a server-kind section still runs as a server (listeners, admission, relay): fail closed, no data plane and no host changes, status problem mode_mismatch, same on a map change to server kind; lab tests that ran a server section as a device's peer → -mode server; RR42, security.md rule 7, agent doc.go, configuration.md, runbook upgrade step
- [ ] R1.2 device-only behaviour keyed on the map's kind (engine.go LocalSourcesOnly, agent/resolver.go): key on the mode, or log why unreachable
- [ ] R1.3 TestAnExitWithNoModeSetForwardsNothing and the lab egress restart check listeners, admitted links and relayed packets, not only egress
- [ ] R1.4 tests: THINKPOL_MODE=auto (78, "gone"), "gone" in the flag case, flag over env precedence
- [ ] R1.5 stale text: localapi.proto MODE_UNSPECIFIED, api-overview-reference.md, keepNoTrace comment, install_test wording, TP-183 credit in configuration.md and settings_test.go, api-overview.md:375, mapfollower comments, crashtrace.go and doc.go "a service's definition gives neither", RR42 When
- [ ] R1.6 one function holds the known-device rule; ServiceMode adds the can-it-run check and says why, install prints the matching hint
- [ ] R1.7 Node.Mode() without report.mu, awaitSection without a local mode copy
- [ ] R1.8 nits: config.go "gone" message and api-overview.md:210, crashtrace test case name, rewrapped comments, dataplane.go:713 warning folded into R1.1

## Log
- 2026-10-18 created in backlog (owner decision: the node's configuration caps the map)
- 2026-10-24 docs: slotted in the pre-M2 phase (wave 1, Agent)
- 2026-11-07 TP-139 verdicts noted
- 2026-11-07 split (owner's MVP cut): only the `device` default stays (PRD A4); the ceiling mechanism → TP-183
- 2026-11-07 backlog → in-progress, owner: agent-tp-111
- 2026-11-07 done: `-mode` defaults to `device`, `auto` is gone (EX_CONFIG 78, "is gone"); the mode comes from flag over env over node.json over the default, never the map's kind; ResolveMode removed; crash trace kept only when node.json says device, or sets no mode and the map shows a device (servers stay trace-free); service install warns a node file without a mode; lab exits run with `-mode server`; docs (agent and service doc.go, configuration.md, api-overview, overlay.md, security.md, RR42, runbook upgrade step for servers that relied on auto)
- 2026-11-07 tests: TestUpRunsANodeAsADeviceUnlessToldOtherwise, TestUpRefusesABadMode, TestAnExitWithNoModeSetForwardsNothing, TestOnlyAKnownDeviceKeepsTracing cases, TestServiceModeIsTheNodesMode cases, lab TestEgressThroughAnExit no-mode restart
- 2026-11-07 mutations: default:"server" fails TestUpRunsANodeAsADeviceUnlessToldOtherwise, TestLoadConfig, TestAnExitWithNoModeSetForwardsNothing; checkMode accepting auto fails TestUpRefusesABadMode, TestPrepareChecksTheConfig, TestServiceModeIsTheNodesMode; knownDevice ignoring the map fails TestOnlyAKnownDeviceKeepsTracing; lab restart with -mode server fails TestEgressThroughAnExit on mode=device and, with the log waits removed, on the fetch getting through
- 2026-11-07 make lint, make test green; full make lab-test green on 7fc726d (LAB_P=4, exclusive CPU lock)
- 2026-11-07 not verified: a real upgrade of a server from a pre-TP-111 binary (runbook step written, not run); the cmd-level failed-start trace test can't tell the map-kind mutation (its state can't read a map), the agent-level test does
- 2026-11-07 in-progress → review
- 2026-11-07 review → has-errors (round 1 findings R1.x)
- 2026-11-08 handoff found: the first round-2 agent stopped (2026-11-07) on a usage limit after 15b8410 (WIP 744f0e9, 2fe7624, 15b8410: R1.1 device mode runs no server's section, R1.6 knownMode, lab servers in server mode, docs, R1.8); nothing ticked, lint/test/lab not run on them
- 2026-11-08 round 2 resumed (agent-tp-111): tree clean at 15b8410; merged origin/rewrite (board streams; `stream: core` added); every WIP change re-read against R1.1–R1.8
- 2026-11-08 R1.1: device mode never runs a server's section: Prepare and run (modeMismatch) start such a node in awaitSection with no restoreHost (no TUN, route, resolver or crashed-run clean-up), the connection held as on a removal; the runner's follower (device = Device set) stops the data plane on a map that makes a running device a server (conn.remove, stop, blobs emptied) and restarts it when a map makes it a device again; Status.ModeMismatch, health problem mode_mismatch, the log says set "mode": "server" in node.json (or -mode server) and restart; dataplane.go's "not an exit here" warning removed (subsumed). Listeners, admission and relaying can't reach device mode otherwise: netmap refuses a device section with listeners, ingress or egress (section.go)
- 2026-11-08 R1.2: no change needed, unreachable wrongly: in device mode a server-kind section never runs (R1.1), so the kind-keyed branches see only device sections there and kind = mode. In server mode a device-kind section runs in a worker (Device nil): engine LocalSourcesOnly (kind device) and resolver.go:60's TunnelControl only narrow it (no OS traffic forwarded, tunnel queries bound to the worker's TUN), engine.go:391 makes no exit of it, and resolver.go:145 checks Device == nil first, so the OS resolver is never pointed from a worker. Keying them on the mode would widen what a map that narrows a server to a device gets
- 2026-11-08 R1.3: TestAnExitWithNoModeSetForwardsNothing is now TestAServerWithNoModeSetRunsNothing (no data plane, no listener: a dial is refused; the device linking to it gets no link up; no host touch through the platform: TUN, configurator, route table, resolver, crashed-run clean-up; status and health mode_mismatch; the log's hint); new TestADeviceTheMapMakesAServerStops (a running device made a server by its map stops its data plane with mode_mismatch, and runs again when a map makes it a device). Lab TestEgressThroughAnExit: server-1 (the relay device-a links to) and then server-2 (the exit) restarted with no mode: mode_mismatch in thinkpol status, nothing on :4500, device-a gets no_link_up and no ping to server-2's overlay address, nothing reaches the internet, the log has no map applied, listening or link up, and the container's resolv.conf, rules, routes, addresses, links and nft ruleset are unchanged
- 2026-11-08 R1.4: up_test cases flag over env, env over node file, THINKPOL_MODE=auto (78, "is gone"), "gone" only for auto in the flag case
- 2026-11-08 R1.5–R1.8 checked against the code: proto (make proto output committed), api-overview(-reference), keepNoTrace, install_test, TP-183 credits, mapfollower comments, crashtrace.go and doc.go clause, RR42 When; knownMode holds the one rule, ServiceMode adds the can-it-run check and returns why (ModeUnknown), install prints the matching hint; Node.Mode() reads cfg.Mode without report.mu, awaitSection has no mode copy; config.go "is gone" message and api-overview.md:210; crash-trace case renamed; no comment line over 80 columns added on the branch
- 2026-11-08 mutations: device mode reporting mode_mismatch but running the section (out() ignoring mismatch, no await, no early stop) fails TestAServerWithNoModeSetRunsNothing (its listener answers), TestADeviceTheMapMakesAServerStops (data plane still up) and lab TestEgressThroughAnExit (server-1 listens, device-a's ping to server-2 answered, the fetch gets through); mismatch never set fails both unit tests; restoreHost on a mismatch fails TestAServerWithNoModeSetRunsNothing (host touched 3 times); the runner ignoring a map that makes it a server fails TestADeviceTheMapMakesAServerStops; THINKPOL_MODE re-applied over the flags fails "a flag over the environment"; the node file over the environment fails "the environment over the node file"; the message without "is gone" fails TestUpRefusesABadMode (flag, env and file cases); knownMode calling a removed node UnknownMapShowsServer fails TestServiceModeIsTheNodesMode; install not hinting UnknownMapShowsServer fails TestOnlyADevicesDefinitionKeepsACrashTrace
- 2026-11-08 make lint, make test green on 1e743af (exclusive CPU lock, GOFLAGS=-p=2)
