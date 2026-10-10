---
id: TP-002
title: "Lab harness"
milestone: M0
area: lab
repo: thinkpol-vpn
size: M
depends_on: [TP-001]
refs: [DESIGN#censor-lab]
owner: "agent-tp-002"
branch: "tp-002-lab-harness"
---

## Goal
A reproducible Docker environment where several thinkpol nodes run on separate networks and Go tests drive them, so every milestone's "done when" is an automated check.

## Scope
- `lab/compose.yaml`: networks `devices` and `servers` joined by a `router` container (the censor sits there later); node containers privileged with `/dev/net/tun` and `NET_ADMIN`; topology: `device-a`, `device-b`, `server-1`, `server-2`, an `internet` target.
- Binaries are cross-compiled on the host (`GOOS=linux CGO_ENABLED=0`) into `lab/bin` and mounted read-only: no Go toolchain and no private-module access inside images.
- Base image: small Debian with iproute2, nftables, iputils, tcpdump, curl.
- Go test package `lab/` behind the `lab` build tag: helpers to exec in a container, wait for conditions, capture packets on the router for assertions.
- `make lab-up` / `lab-test` / `lab-down`; `lab-test` brings the lab up, runs the tests, tears it down. They replace the placeholders TP-001 left in the Makefile.
- `make lab`, which DESIGN.md "Censor lab" and TP-024 refer to: an alias of `lab-test` for now; TP-024 makes it run the full matrix and regenerate `lab/RESULTS.md`.
- A smoke test proving the harness: `device-a` reaches the `internet` target through the router (no thinkpol yet).
- Lab runs are isolated per worktree, so several agents can run `make lab-test` at the same time: the Compose project name is derived from the worktree/branch, no fixed `container_name`s, and no fixed subnets (let Docker allocate them, or allocate them per project without collisions). Helpers address containers through the project, never by a hard-coded name.

## Out of scope
Censor modules (TP-024 onwards).

## Acceptance
- [x] `make lab-test` passes from a clean checkout with only Docker and Go installed (with `lab/bin` and `lab/.run` removed: green in ~13 s warm; the very first run, building the image without a layer cache, took ~52 s; `make lint` and `make test` green too)
- [x] tests can capture and inspect packets at the router (`TestSmoke`: a UDP datagram's payload and ICMP echo, IPv4 and IPv6, seen arriving on `devices` and leaving on `servers`)
- [x] `lab/README.md` explains how to add a node and a test
- [x] two lab runs from two worktrees run concurrently without interfering (no shared container names, networks or subnets; tearing one down leaves the other running): `make lab-test` in this worktree and in a second one at the same commit ran at the same time, both green (13.9 s and 14.3 s), while this worktree's `make lab-up` lab stayed up; the projects were `<checkout>-<hash>[-t-<test>-<hash>]`, every network got its own Docker-allocated IPv4 /16 and ULA /64; `make lab-down` in the second worktree removed only its own lab, and this one's still pinged across the router afterwards. `TestLabsAreIsolated` checks the same inside one run.

## Notes
- **No `lab/compose.yaml`.** Per the orchestration hotspot ("tests declare the nodes they need instead of editing one shared topology"), topologies are Go values (`lab.Standard()`, `Topology.With`, `WithNetworks`) rendered per lab to `lab/.run/<project>/compose.json` (ignored). `make lab-up` prints the path for a human to read.
- **Test API** (package `lab`, untagged so lint and `make test` cover it; the Docker tests are `//go:build lab`): `lab.Start(t, topo) *Lab` (own Compose project per test, torn down at the end, logs on failure, `THINKPOL_LAB_KEEP=1` keeps a failed lab); `l.Node(name)` → `IPv4/IPv6(network)`, `Exec(ctx, ...)`, `MustExec(t, ...)`, `WriteFile(t, path, data)`, `Start(t, ...) *Process`, `Capture(t, filter) *Capture` (`WaitFor`, `Packets`, `Stop`; `Packet` has addresses, ports, payload, network and direction), `RunGoTests(t, pattern, args...)`; `lab.Eventually(t, timeout, cond)`.
- **In-node tests (TP-007 and every root/netns test):** `make lab-test` runs `labctl gotest ./...`, which compiles every package's tests for linux and runs them as root in a lone privileged node with `THINKPOL_LAB=1`, cwd = the package dir under `/src`. One package: `make lab-gotest PKG=./internal/dataplane/netcfg/... RUN=regexp`. Packages run one after another in the same node, so tests must clean up their namespaces/links.
- **Docker facts checked on this setup (Docker 27, linuxkit 6.10 kernel):** IPv6 networks without a subnet get a ULA /64 automatically; `/dev/net/tun`, `ip netns`, nftables and an nftables `queue` rule all work in a privileged node (good news for TP-024's NFQUEUE). tcpdump `-i any` writes LINUX_SLL2; the decoder also takes SLL, Ethernet and raw.
- **Gotchas:** Docker `internal: true` networks drop forwarded IPv4 between them (bridge netfilter), so lab networks are ordinary ones and the harness deletes Docker's default routes instead: no node can reach outside the lab. The router sees each forwarded packet twice (in and out). Capture needs `--immediate-mode` (already set) or the last packets before `Stop` are lost. Docker's default address pools hold ~30 networks daemon-wide; the standard topology takes two.
- **For downstream tickets:** TP-012/TP-010/TP-014/TP-018 add `//go:build lab` tests in `lab/` declaring their topology (servers already have forwarding on; `internet` sits on the servers side, so traffic to it from a device crosses the router in plaintext unless tunneled). TP-024 puts the censor on the `router` node (`Command`, or `Start` a process) and makes `make lab` run the matrix. A depguard rule keeps `cmd/` and `internal/` from importing `lab`.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-002, branch: tp-002-lab-harness
- 2026-10-10 in-progress → review — make lint, make test, make lab-test green; concurrent lab-test from two worktrees green
