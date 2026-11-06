---
id: TP-192
title: "Supervisor: per-space cgroup directories survive a crash and uninstall"
milestone: later
area: agent
repo: thinkpol-vpn
size: S
depends_on: []
refs: [docs/design/security.md#node-safety]
owner: ""
branch: ""
---

## Goal
A server's per-space cgroup directories don't outlive it: they are removed after a crash and by uninstall.

## Scope
- The supervisor creates a cgroup directory per space under `/sys/fs/cgroup/thinkpol/`. After a server crash, and after uninstall, they stay.
- On start, remove leftover empty space directories the supervisor no longer runs; uninstall removes the whole `thinkpol` subtree once its processes are gone.

## Out of scope
- Uninstall's other steps: TP-132.

## Acceptance
- [ ] a lab test: after a killed server and a restart, no stale space directory remains
- [ ] after uninstall, `/sys/fs/cgroup/thinkpol/` is gone
- [ ] the `supervisor` package doc says who removes the directories
- [ ] `make lint`, `make test` and `make lab-gotest PKG=./internal/agent/supervisor/...` pass

## Notes
- Found in TP-132's round-1 review, 2026-11-07.

## Log
- 2026-11-07 created in backlog
