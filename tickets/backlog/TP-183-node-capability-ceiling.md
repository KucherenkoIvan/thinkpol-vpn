---
id: TP-183
title: "The node's own configuration caps the map"
milestone: later
area: agent
stream: core
repo: thinkpol-vpn
size: M
depends_on: [TP-111]
split_from: TP-111
refs: [docs/design/overlay.md#node-agent]
owner: ""
branch: ""
---

## Goal
A node does only what it was allowed to on the machine itself. The space's signed map acts within that ceiling and can never widen it (PRD Decisions, "The node's own configuration caps the map").

## Scope
- The ceiling, in the node's local configuration (the node file from TP-166; flags for the lab and development): a preset, `device` (the default) or `server`, and within `server` each capability on its own: ingress, egress (with `EgressAllowed`), relaying.
- The node checks what the map asks of it against the ceiling:
  - at start, a map that asks for more leaves the node down: a health problem says what was asked and what is allowed, and it carries no traffic;
  - while running, a newer map that asks for more: the node keeps its last accepted capabilities, takes the rest of the map (peers, keys, revocations, routes), and reports the refusal in health and in the log; it saves only what it accepted, so a restart comes back to that;
  - the owner lowering the ceiling under a running map is handled the same way.
- A `device` node never answers names as an exit, never listens publicly and never forwards: the half-state of a server section run in device mode is gone.
- macOS: a `server` preset is refused with "server nodes need Linux", with no suggestion to run as a device.
- docs/runbook-pre-controller.md: the operator sets the ceiling on each server.
- Lab: TestDNSFollowsTheRules and TestASecondAgentChangesNothing run their exits in server mode (TP-098 made server-mode exits resolve); the blob-tampering test needs another way to stage a tampered peer, since it relies on a server section run in device mode today (corrupt the peer's seed only if the server serves without checking it; otherwise a stand-in inside the worker's namespace).

## Out of scope
- The `device` default of `-mode`: TP-111.
- Nodes advertising their ceiling to the controller, and the builder refusing to publish a map that asks for more: M4 (TP-034, TP-038).
- Devices as exits or as routers into a home network: after the MVP (docs/design/milestones.md, Out of scope).

## Acceptance
- [ ] lab: a node whose map asks for more than its ceiling at start is down, with the health problem, and carries no traffic
- [ ] lab: a running node given a newer map that asks for more keeps its capabilities, takes the map's other changes (a revoked peer is refused), reports the refusal, and comes back to the same state after a restart
- [ ] lab: the owner lowering the ceiling under a running map is refused the same way
- [ ] unit tests: each capability is checked on its own
- [ ] docs/design/overlay.md's "planned" on the ceiling is removed
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Split from TP-111, 2026-11-07, owner's MVP cut.
- Owner decisions 2026-10-18: default `device`, opted into locally (Tailscale's model); a mismatch at start brings the node down; a mismatch at runtime keeps the last accepted capabilities and reports, never blocking the rest of the map (refusing a whole map would also refuse revocations and key rotations).
- **TP-139 verdicts (2026-11-07; docs/design/api-overview.md "Verdicts", docs/design/configuration.md).** The ceiling lives in the node file that TP-166 builds; the map can only narrow it. Its problem code is snake_case (F5); its switches are `on|off` toggles and its setting has the `<setting> [value]` shape (F6, F7); a bad value exits EX_CONFIG (78). Where accepted capabilities are kept stays this ticket's to decide (the node file holds operating settings only, no history).

## Log
- 2026-11-07 created in backlog (split from TP-111)
