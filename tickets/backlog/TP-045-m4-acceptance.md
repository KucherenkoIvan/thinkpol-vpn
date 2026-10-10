---
id: TP-045
title: "M4 acceptance: isolation and seizure checks"
milestone: M4
area: lab
repo: thinkpol-vpn
size: M
depends_on: [TP-037, TP-038, TP-040, TP-041, TP-042, TP-043]
refs: [DESIGN#censor-lab]
owner: ""
branch: ""
---

## Goal
M4's "done when": provisioning, sharing, isolation and seizure safety proven in the lab.

## Scope
- A fresh container joins through `node add` and appears on the canvas.
- A second space shares the entry; isolation suite: reachability and scans across spaces, route and DNS leaks between namespaces.
- Seizure check: dump a node's disk and process memory, search for member IPs, names, destinations and readable telemetry.

## Acceptance
- [ ] isolation and seizure checks green and part of `make lab`

## Log
- 2026-10-10 created in backlog
