---
id: TP-272
title: "The worker sandbox leaves an empty thinkpol-root dir in /tmp on each start"
milestone: later
area: agent
stream: core
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
`internal/agent/worker/sandbox_linux.go` (~:108) makes its new root with `os.MkdirTemp("", "thinkpol-root")` and leaves the empty directory in the host's `/tmp` on every worker start. Remove it after `pivot_root`, or use a fixed path under the state directory.

## Acceptance
- [ ] No leftover after a worker start and stop (a test).

## Log
- 2026-11-20 created in backlog (TP-269 review)
