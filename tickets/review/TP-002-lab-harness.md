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
  - After the review fixes (`be20e07`): repeated. Both `make lab-test` runs green at the same time (21.7 s and 28.2 s) with this worktree's `make lab-up` lab up; every network had its own /24 from 172.16.0.0/16 and its own ULA /64; `make lab-down` in the second worktree removed only `tplab-tp-002-lab-harness-b-…`, and this worktree's device-a still pinged `internet` by name afterwards. Warm `make lab-test` alone: ~21 s.

## Notes
- **No `lab/compose.yaml`.** Per the orchestration hotspot ("tests declare the nodes they need instead of editing one shared topology"), topologies are Go values (`lab.Standard()`, `Topology.With`, `WithNetworks`) rendered per lab to `lab/.run/<project>/compose.json` (ignored). `make lab-up` prints the path for a human to read.
- **Test API** (package `lab`, untagged so lint and `make test` cover it; the Docker tests are `//go:build lab`): `lab.Start(t, topo) *Lab` (own Compose project per test, torn down at the end, logs on failure, `THINKPOL_LAB_KEEP=1` keeps a failed lab); `l.Node(name)` → `IPv4/IPv6(network)`, `Exec(ctx, ...)`, `MustExec(t, ...)`, `WriteFile(t, path, data)`, `Start(t, ...) *Process`, `Capture(t, filter) *Capture` (`WaitFor`, `Packets`, `Stop`; `Packet` has addresses, ports, payload, network and direction), `ExportFS(ctx, w)`, `RunGoTests(t, pattern, args...)`; `l.DockerGateways(network)`; `lab.Eventually(t, timeout, cond)`.
- **API changes from the review fixes** (everything above kept its signature): `CheckoutProject(root)` now returns `(string, error)` and every project name starts with `tplab-`; `DownCheckout(ctx, root, onlyTests)` lost its `checkout` argument; new `DownStale`, `GoTestEach`, `Node.ExportFS`, `Lab.DockerGateways`, `NodeSpec.Privileged`, `DefaultTestTimeout` and the constants `ProjectPrefix`, `LabelLab`, `LabelRoot`, `MaxLabsEnv`, `SubnetPoolEnv`. Behaviour: nodes are no longer privileged (NET_ADMIN, NET_RAW, SYS_ADMIN, /dev/net/tun, AppArmor off, `/proc/sys/net` writable); DNS inside nodes only knows lab node names (`/etc/hosts`); in-node test binaries get `-test.timeout=10m` unless given one; `labctl gotest` runs each package in a fresh lab.
- **In-node tests (TP-007 and every root/netns test):** `make lab-test` runs `labctl gotest ./...`, which compiles every package's tests for linux and runs each package as root in a fresh lab node of its own with `THINKPOL_LAB=1`, cwd = the package dir under `/src`, four packages at a time. One package: `make lab-gotest PKG=./internal/dataplane/netcfg/... RUN=regexp`. Checked without privileged: TUN, `ip netns`, veths into namespaces, nftables incl. a `queue` rule, net sysctls in the node and in namespaces.
- **Safety:** projects are `tplab-…`; containers and networks carry `org.thinkpol.lab=1` and `org.thinkpol.lab.root`; tear-down lists by label and refuses a project with any unlabelled container or network (`TestDownRefusesUnlabelledResources` proves it on a throwaway look-alike project and on a lab joined by a foreign container; `TestDownRefusesProjectsWithoutThePrefix`), never `--volumes`. The image's own label is `org.thinkpol.lab.image`, because containers inherit image labels.
- **Hermeticity:** default routes deleted, Docker's bridge addresses blackholed (v4 and v6) on every node including the router, no masquerade on lab networks, `resolv.conf` pointing at nothing. `TestSmoke/hermetic` checks no default route on the router, no outside address, no Docker gateway (v4/v6) from any node, no outside name, and that Docker's own resolver at 127.0.0.11 answers lab names but not outside ones.
- **Subnets and capacity:** /24s from `172.16.0.0/16` (below Docker's default pools) plus a random ULA /48 per lab, checked against every daemon network under a host-wide lock file, retried on overlap; at most 12 labs from tests at once host-wide (`THINKPOL_LAB_MAX_LABS`); `labctl down -stale` (run first by `make lab-test`) removes labs whose checkout is gone, checked by removing a probe worktree with a lab up.
- **Image:** Debian bookworm-slim pinned by digest; wireguard-tools, openssl (`s_server`), nginx-light and netcat added for TP-012/024 (+3 MB, 177 MB total).
- **Gotchas:** Docker `internal: true` networks drop forwarded IPv4 between them (bridge netfilter), so lab networks are ordinary ones, sealed as above. The router sees each forwarded packet twice (in and out). Capture uses `--immediate-mode`, or the last packets before `Stop` are lost. `getent hosts` prefers IPv6 (use `ahostsv4`).
- **For downstream tickets:** TP-012/TP-010/TP-014/TP-018 add `//go:build lab` tests in `lab/` declaring their topology (servers already have forwarding on; `internet` sits on the servers side, so traffic to it from a device crosses the router in plaintext unless tunneled). TP-024 puts the censor on the `router` node (`Command`, or `Start` a process) and makes `make lab` run the matrix. TP-045 reads a node's disk with `ExportFS`. A depguard rule keeps `cmd/` and `internal/` from importing `lab`.

## Review findings
Accepted by the orchestrator, 2026-10-10.

- [x] B1 Owner-stack safety: `THINKPOL_LAB_PROJECT=infra make lab-down` would `compose down --volumes` a foreign project. Every lab project gets a fixed `tplab-` prefix no override can remove; every service and network is labelled `org.thinkpol.lab=1` and `org.thinkpol.lab.root=<checkout>`; DownCheckout lists candidates only by that label; downProject refuses unless every container and network of the project carries it; no `--volumes`; overrides validated. The refusal path is tested against a throwaway unlabelled project.
- [x] B2 Hermeticity: overwrite each node's resolv.conf (no upstream forwarding by Docker's DNS); blackhole routes to each lab network's Docker gateway (v4 and v6) on every node including the router; `enable_ip_masquerade: "false"` on lab networks; the hermetic subtest checks no external DNS, unreachable gateways (v4/v6), no default route out. README and Notes corrected.
- [x] S1 Explicit subnets from a dedicated range outside Docker's default pools, checked against the daemon's networks, retried on overlap; a host-wide limit on concurrent labs (configurable); `labctl down --stale` removes labelled labs whose checkout is gone, run at the start of lab-test.
- [x] S2 Tear down an existing lab of the same project before `up`.
- [x] S3 No `privileged` by default: NET_ADMIN, NET_RAW, SYS_ADMIN and /dev/net/tun (other relaxations only if needed); privileged only as an explicit per-node opt-in. An export helper for TP-045 (a node's filesystem); README rule: tests never touch block devices.
- [x] S4 Default `-test.timeout=10m` for in-node test binaries; labctl contexts with deadlines.
- [x] S5 Each package's in-node tests run in a fresh node.
- [x] S6 Test binaries built via os.CreateTemp, one build per package at a time, unique binary names.
- [x] S7 `make lab-test` skips the final down when THINKPOL_LAB_KEEP is set.
- [x] S8 `labctl up` tears down on configure failure; configure errors are joined.
- [x] S9 Base image pinned by digest.
- [x] Nits: `--platform` passed consistently (GOARM on arm); RUN passed quote-safely to labctl; project names never start with `-`.
- [x] Image additions for TP-012/024 (wireguard-tools, an HTTP/TLS server) if cheap, otherwise listed in Notes.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-002, branch: tp-002-lab-harness
- 2026-10-10 in-progress → review — make lint, make test, make lab-test green; concurrent lab-test from two worktrees green
- 2026-10-10 review → has-errors — two blockers (B1 owner-stack safety, B2 hermeticity) and should-fixes, see Review findings
- 2026-10-10 has-errors → in-progress — owner: agent-tp-002, fixing the review findings
- 2026-10-10 in-progress → review — review findings fixed (be20e07); make lint, make test, make lab-test green; concurrent lab-test from two worktrees green again
