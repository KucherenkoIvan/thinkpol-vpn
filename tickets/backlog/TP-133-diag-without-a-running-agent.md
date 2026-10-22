---
id: TP-133
title: "`thinkpol diag` as root without a running agent"
milestone: M2
area: agent
repo: thinkpol-vpn
size: S
depends_on: [TP-091]
refs: [docs/design/desktop-client.md#the-local-api]
owner: ""
branch: ""
---

## Goal
After a crash (kill -9, power loss) `thinkpol diag` still records what the dead agent left on the host: the evidence a device run needs most is the state after a crash, and today `diag` needs a running agent to answer.

## Scope
- When the local API doesn't answer, root's `diag` reads the host itself with the same readers the agent uses (netcfg, firewall, dns: routes and records, the guard's table/anchor and pf reference, the resolvers) and writes the same versioned snapshot, with `agent: "not running"` and the agent-only parts (status, TUN, last Apply) unreadable with that reason.
- Read-only, exactly as the agent's readers are: no lock taken, no directory made. A non-root caller without an agent gets an error, not a partial snapshot.
- The schema version stays 1 if only a value is added; say so.

## Acceptance
- [ ] lab: SIGKILL a connected device's agent, then `diag -o` as root records its leftover routes, guard and resolver configuration, matching `ip -j`, `nft -j` and resolvectl
- [ ] a unit test: no agent and no root → an error
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Owner's answer to the device-harness questions (2026-10-23, TP-082 question 2). The harness's crash steps use it.

## Log
- 2026-10-23 created in backlog (TP-082 design answers)
