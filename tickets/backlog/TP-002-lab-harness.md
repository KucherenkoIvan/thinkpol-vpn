---
id: TP-002
title: "Lab harness"
milestone: M0
area: lab
repo: thinkpol-vpn
size: M
depends_on: [TP-001]
refs: [DESIGN#censor-lab]
owner: ""
branch: ""
---

## Goal
A reproducible Docker environment where several thinkpol nodes run on separate networks and Go tests drive them, so every milestone's "done when" is an automated check.

## Scope
- `lab/compose.yaml`: networks `devices` and `servers` joined by a `router` container (the censor sits there later); node containers privileged with `/dev/net/tun` and `NET_ADMIN`; topology: `device-a`, `device-b`, `server-1`, `server-2`, an `internet` target.
- Binaries are cross-compiled on the host (`GOOS=linux CGO_ENABLED=0`) into `lab/bin` and mounted read-only: no Go toolchain and no private-module access inside images.
- Base image: small Debian with iproute2, nftables, iputils, tcpdump, curl.
- Go test package `lab/` behind the `lab` build tag: helpers to exec in a container, wait for conditions, capture packets on the router for assertions.
- `make lab-up` / `lab-test` / `lab-down`; `lab-test` brings the lab up, runs the tests, tears it down.
- A smoke test proving the harness: `device-a` reaches the `internet` target through the router (no thinkpol yet).
- Lab runs are isolated per worktree, so several agents can run `make lab-test` at the same time: the Compose project name is derived from the worktree/branch, no fixed `container_name`s, and no fixed subnets (let Docker allocate them, or allocate them per project without collisions). Helpers address containers through the project, never by a hard-coded name.

## Out of scope
Censor modules (TP-024 onwards).

## Acceptance
- [ ] `make lab-test` passes from a clean checkout with only Docker and Go installed
- [ ] tests can capture and inspect packets at the router
- [ ] `lab/README.md` explains how to add a node and a test
- [ ] two lab runs from two worktrees run concurrently without interfering (no shared container names, networks or subnets; tearing one down leaves the other running)

## Log
- 2026-10-10 created in backlog
