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
