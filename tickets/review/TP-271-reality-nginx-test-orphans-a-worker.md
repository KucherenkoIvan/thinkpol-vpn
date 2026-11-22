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
- [x] No extra process after the test: the reset's log after the package (`make lab-gotest PKG=./internal/dataplane/transport/reality/...`, `-v`) shows none. On rewrite 6832b93c the reset killed `process 175 nginx: worker process`; on 3412bb09 it killed nothing, with TestAfterTheLabSitesFINTheSameWriteFails run and passing.

## Log
- 2026-11-20 created in backlog (TP-269 review)
- 2026-11-22 backlog → in-progress, owner: agent-tp-271
- 2026-11-22 startLabSite runs nginx with `-g "daemon off; master_process off;"` (nginx_test.go ~53): one process, so the cleanup's kill leaves no worker behind; the TLS and TCP behaviour the test compares is the worker's either way
- 2026-11-22 lab, `make lab-gotest PKG=./internal/dataplane/transport/reality/...` (-v): rewrite 6832b93c, the reset killed `nginx: worker process` (112 s); 3412bb09 (rewrite merged in), the reset killed nothing (379 s, 230 s of it waiting for a slot). nginx's verdicts are the same in both runs (tls_record and sslv2: write 2 failed; text: 4 writes went through), on nginx and through the listener. No new test, so no mutation: the base run is the check without the fix. No full `make lab-test`: the orchestrator runs full labs on rewrite after merges
- 2026-11-22 make lint and make test green on 3412bb09
- 2026-11-22 in-progress → review
