---
id: TP-199
title: "Version the map schema before the controller"
milestone: M4
area: netmap
stream: administration
repo: thinkpol-vpn
size: M
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
The map carries a schema version and a written compatibility rule, so the controller and the nodes can move separately. The map is the most-imported package in the tree (agent, dataplane, rules, wg, lists, worker, supervisor, blobs, devmap and cmd import netmap): without a version, any change to it is a change to every package at once and to every node in the field.

## Scope
- A schema version field in the map envelope, set by everything that writes a map (the controller later, the dev-map tooling now).
- A written compatibility rule, in the design docs: what a node does with a map of an older version, a newer version, and a map with unknown fields; what error a refused map produces and which exit code the CLI returns for it.
- The node enforces the rule when it loads a map; the dev-map tooling writes the current version.
- Add this ticket to the controller ticket's `depends_on` (TP-034), so the controller cannot start first.

## Out of scope
- A migration tool between versions: there is one version until the controller exists.
- The controller itself (TP-034).

## Acceptance
- [ ] A map with no version, or with a newer version than the node knows, is refused; evidence: a unit test per case, and the error text names both versions.
- [ ] A map of the current version with an unknown field loads and the field is ignored; evidence: a unit test.
- [ ] A refused map makes the CLI exit with the code the rule names; evidence: a CLI test on the exit code.
- [ ] The rule is written in the design docs and the tests cite it; evidence: the doc section and a `make lint` pass with the ref check.
- [ ] `make lint`, `make test`, `make lab-test` pass.

## Notes
- Source: stream review 2026-11-07 (orchestrator).
- A change to the map schema touches the administration and core streams; this ticket is where that contract gets its rule.

## Log
- 2026-11-08 created in backlog
