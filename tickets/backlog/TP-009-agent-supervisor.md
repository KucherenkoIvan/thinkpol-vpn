---
id: TP-009
title: "Server agent: supervisor and per-space workers"
milestone: M0
area: agent
repo: thinkpol-vpn
size: L
depends_on: [TP-001, TP-007]
refs: [N5, DESIGN#server-agent-one-worker-per-space]
owner: ""
branch: ""
---

## Goal
A server node runs a supervisor and one worker process per space, each worker in its own network namespace, from the start, even while it serves one space.

## Scope
- Supervisor in the root namespace: reads which spaces the node serves, creates a network namespace and a veth pair per space, starts `thinkpol worker --space <id>` inside it, restarts crashed workers with backoff, stops everything cleanly.
- Entering the namespace safely from Go (locked OS thread before exec, or re-exec into the namespace).
- One Unix socket per worker for control and connection handoff (used by TP-010).
- Linux only (build tags).

## Acceptance
- [ ] killing one worker restarts it and leaves other workers untouched
- [ ] stopping the supervisor removes all namespaces and veths
- [ ] a worker can't see the root namespace's interfaces

## Log
- 2026-10-10 created in backlog
