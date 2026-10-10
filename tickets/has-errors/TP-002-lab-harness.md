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

## Review findings
Accepted by the orchestrator, 2026-10-10.

- [ ] B1 Owner-stack safety: `THINKPOL_LAB_PROJECT=infra make lab-down` would `compose down --volumes` a foreign project. Every lab project gets a fixed `tplab-` prefix no override can remove; every service and network is labelled `org.thinkpol.lab=1` and `org.thinkpol.lab.root=<checkout>`; DownCheckout lists candidates only by that label; downProject refuses unless every container and network of the project carries it; no `--volumes`; overrides validated. The refusal path is tested against a throwaway unlabelled project.
- [ ] B2 Hermeticity: overwrite each node's resolv.conf (no upstream forwarding by Docker's DNS); blackhole routes to each lab network's Docker gateway (v4 and v6) on every node including the router; `enable_ip_masquerade: "false"` on lab networks; the hermetic subtest checks no external DNS, unreachable gateways (v4/v6), no default route out. README and Notes corrected.
- [ ] S1 Explicit subnets from a dedicated range outside Docker's default pools, checked against the daemon's networks, retried on overlap; a host-wide limit on concurrent labs (configurable); `labctl down --stale` removes labelled labs whose checkout is gone, run at the start of lab-test.
- [ ] S2 Tear down an existing lab of the same project before `up`.
- [ ] S3 No `privileged` by default: NET_ADMIN, NET_RAW, SYS_ADMIN and /dev/net/tun (other relaxations only if needed); privileged only as an explicit per-node opt-in. An export helper for TP-045 (a node's filesystem); README rule: tests never touch block devices.
- [ ] S4 Default `-test.timeout=10m` for in-node test binaries; labctl contexts with deadlines.
- [ ] S5 Each package's in-node tests run in a fresh node.
- [ ] S6 Test binaries built via os.CreateTemp, one build per package at a time, unique binary names.
- [ ] S7 `make lab-test` skips the final down when THINKPOL_LAB_KEEP is set.
- [ ] S8 `labctl up` tears down on configure failure; configure errors are joined.
- [ ] S9 Base image pinned by digest.
- [ ] Nits: `--platform` passed consistently (GOARM on arm); RUN passed quote-safely to labctl; project names never start with `-`.
- [ ] Image additions for TP-012/024 (wireguard-tools, an HTTP/TLS server) if cheap, otherwise listed in Notes.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-002, branch: tp-002-lab-harness
- 2026-10-10 in-progress → review — make lint, make test, make lab-test green; concurrent lab-test from two worktrees green
- 2026-10-10 review → has-errors — two blockers (B1 owner-stack safety, B2 hermeticity) and should-fixes, see Review findings
