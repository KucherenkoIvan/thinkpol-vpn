---
id: TP-271
title: "The reality transport's nginx test leaves an orphaned worker"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-271"
branch: "tp-271-nginx-orphan-worker"
---

## Goal
`internal/dataplane/transport/reality/nginx_test.go` (~:50-56) SIGKILLs the nginx master, which orphans its worker; the lab's reset kills it after the package (TP-269's node pool logs it). Run nginx with `-g "daemon off; master_process off;"`, or stop it cleanly, so the test leaves no process behind.

## Acceptance
- [ ] No extra process after the test: the reset's log after the package (`make lab-gotest PKG=./internal/dataplane/transport/reality/...`, `-v`) shows none.

## Log
- 2026-11-20 created in backlog (TP-269 review)
- 2026-11-22 backlog → in-progress, owner: agent-tp-271
