---
id: TP-158
title: "Lab flake: the forged ICMP errors test loses the root's conntrack flow under load"
milestone: M2
area: agent/supervisor
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: ""
branch: ""
---

## Goal
`TestForgedICMPErrorsAreRefused/bound=true` (internal/agent/supervisor/egress_linux_test.go) passes under a full, loaded lab run.

## Scope
- Seen 2026-10-29 in a full lab run: "the root's conntrack flow expired before the forged errors were counted: the test proves nothing". It passed on re-run. TP-120 already moved the root's dial to just before the errors are sent.
- Likely cause: the root's UDP flow is unreplied, so it expires after `nf_conntrack_udp_timeout` (30 s by default), and the bound case waits up to 15 s each in two `awaitDrops` calls before `rootFlowTracked` checks it.
- Fix direction, say which in Notes: keep the flow alive while waiting (a write from the root's socket refreshes it), raise the UDP timeout in the test's namespace, or shorten the waits. The check that the flow is still tracked stays: without it the test proves nothing.

## Out of scope
- Other flakes: TP-120, TP-147.

## Acceptance
- [ ] the test passes `make lab-gotest PKG=./internal/agent/supervisor/... COUNT=20` with another lab or `make test` loading the host
- [ ] the `rootFlowTracked` check still fails the test when the flow is gone (mutation: never refreshing the flow and an artificial wait past the timeout fails it)
- [ ] `make lint`, `make test` pass

## Notes
- Source: full lab run, 2026-10-29.

## Log
- 2026-10-29 created in backlog (lab flake seen in a full run)
