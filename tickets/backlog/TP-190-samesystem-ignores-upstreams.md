---
id: TP-190
title: "agent: `sameSystem` ignores `Upstreams`"
milestone: later
area: agent
stream: core
repo: thinkpol-vpn
size: S
depends_on: []
refs: [R4]
owner: ""
branch: ""
---

## Goal
A config that changes only the DNS upstreams reaches the OS configuration, and the host's upstreams don't overwrite them later.

## Scope
- `sameSystem` in `internal/agent/resolver.go` compares `Interface`, `Servers` and `Search` but not `Upstreams`. A later config that sets DNS upstreams is taken as the same System, so it is never applied, and on the next resolv.conf change the host's upstreams overwrite them.
- Compare `Upstreams` too, or say in a comment why a field is left out.

## Out of scope
- How upstreams are read from the OS: `dns` package.

## Acceptance
- [ ] a test: a config that changes only `Upstreams` updates the System
- [ ] after that, a resolv.conf change keeps the configured upstreams
- [ ] `make lint`, `make test` pass

## Notes
- Found in TP-130's round-1 review, 2026-11-07.

## Log
- 2026-11-07 created in backlog
