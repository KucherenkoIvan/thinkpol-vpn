---
id: TP-009
title: "Server agent: supervisor and per-space workers"
milestone: M0
area: agent
repo: thinkpol-vpn
size: L
depends_on: [TP-001, TP-007]
refs: [N5, DESIGN#server-agent-one-worker-per-space]
owner: "agent-tp-009"
branch: "tp-009-agent-supervisor"
---

## Goal
A server node runs a supervisor and one worker process per space, each worker in its own network namespace, from the start, even while it serves one space.

## Scope
- Supervisor in the root namespace: reads which spaces the node serves, creates a network namespace and a veth pair per space, starts `thinkpol worker --space <id>` inside it, restarts crashed workers with backoff, stops everything cleanly.
- Entering the namespace safely from Go (locked OS thread before exec, or re-exec into the namespace).
- One Unix socket per worker for control and connection handoff (used by TP-010).
- Linux only (build tags).

## Acceptance
- [x] killing one worker restarts it and leaves other workers untouched — `TestKilledWorkerRestartsAlone` (SIGKILL to space A's worker: A is back with a new pid, `Starts` 2, the same veth name, `LastExit` "signal: killed"; B keeps its pid, `Starts` 1, its namespace inode and its root veth's ifindex, and still receives from the root namespace); `TestCrashingWorkerBacksOff` (a worker failing on every start: restarts at 50/100/200/400 ms, bounded count, its output kept in the ring, the healthy worker untouched)
- [x] stopping the supervisor removes all namespaces and veths — `TestCloseRemovesEverything` (after `Close`: worker pids gone, the workers' net namespace inodes held by no process, thread, descriptor or mount on the node, root links exactly as before, nftables table gone, no proto-85 route left, no named namespace); `TestSupervisorDeathKillsWorkers` (SIGKILL to a supervisor process: its workers die, their veths go with their namespaces, the next supervisor starts and serves); `TestSetSpacesAddsAndRemoves` (removing a space stops its worker and deletes its veth, the freed slot is reused)
- [x] a worker can't see the root namespace's interfaces — `TestWorkersAreSandboxed` (each worker, from inside: netlink and `/sys/class/net` list exactly what a fresh namespace has plus `veth0`; `/proc` lists only itself; `/run` holds only its own `thinkpol`; net, pid and mount namespaces differ from the root's and each other's; from outside: own uid/gid per worker, `CapEff`/`CapPrm`/`CapBnd` = NET_ADMIN|NET_BIND_SERVICE, nothing inheritable or ambient, `NoNewPrivs` 1; it can still create a TUN, bind :53 and set its own net sysctls, and can't open raw sockets, write other sysctls, mount or setuid); `TestNoPacketCrossesSpaces` (with forwarding on in the node, each worker sends to the other space, both veths' root ends and the node's addresses for 2 s: nothing arrives anywhere, while the root namespace reaches both spaces over IPv4 and IPv6; negative control run once with the nftables table disabled: datagrams crossed both ways and reached the root namespace, so the test is not vacuous)
- Evidence: `make lint`, `make test` green; `make lab-gotest PKG=./internal/agent/...` (ipc, logring, supervisor, worker) green 5 runs in a row on the final code, the supervisor package ~30 more runs before the last fix; `go run ./lab/labctl gotest ./...` (every package in a lab node) green, 10 packages; `make lab-test`'s Docker lab tests green (its gotest phase once aborted on a lab-harness race, a Docker network of another checkout vanishing during subnet allocation, and was rerun green)

## Notes
**Process model.**
- `supervisor.New(Options)` takes the node's supervisor role (`netcfg.New(OwnerSupervisor)` in the root namespace, held for life: a second supervisor gets `netcfg.ErrBusy`), sweeps a dead predecessor's leftovers (proto-85 routes, `tp-space*` veths, its nftables table) and installs the isolation table. `SetSpaces(ids)` reconciles (serialized; waits for removed workers to be gone); `Workers()` (`WorkerInfo{Space, Link, RootAddrs, SpaceAddrs, UID, PID, Ready, Starts, LastExit}`), `Output(space)` (the worker's stdout/stderr ring), `Close()`. Linux `&& !android`; elsewhere `New` returns `ErrUnsupported`.
- A worker is `thinkpol worker -space <hex>` (hidden command), exec'd by default from `/proc/self/exe`, so it is always the supervisor's own build even after the file on disk is replaced. `SysProcAttr`: `Cloneflags` NEWPID, `Unshareflags` NEWNET|NEWNS (the runtime remounts `/` private), `Pdeathsig` SIGKILL; environment empty; stdin `/dev/null`; stdout+stderr into a per-space `logring.Ring` (64 KiB). Started from a goroutine locked to its OS thread until the child is reaped: the parent-death signal follows the forking thread, and Go ends a thread whose goroutine exits locked.
- No orphans, three ways: parent-death SIGKILL (re-armed by the worker after it changes user, which clears it), socket EOF (the worker exits when the supervisor's end closes), and namespaces that exist only as long as their worker (no `/run/netns` bind mounts). A SIGKILLed supervisor leaves only its nftables table, which the next one replaces.
- Per incarnation: socketpair → start → open `/proc/<pid>/ns/net` (held until cleanup) → veth with the peer created directly in that namespace (`PeerNamespace`) → Init → wait Ready (`ReadyTimeout` 10 s) → serve. Stop: `KindStop`, `StopTimeout` (5 s), then SIGKILL. Cleanup order: process reaped, space configurator closed, root veth deleted (takes the pair, addresses and connected routes), namespace fd closed. A crashed worker restarts in a fresh namespace: no state to reconcile.
- Backoff: `Initial` 500 ms, doubling to `Max` 30 s; a worker that ran `ResetAfter` (1 min) starts over.
- Worker sandbox (`worker.Run`, before anything untrusted is read): refuses unless PID 1 of its own namespace; reads Init; makes mounts private; mounts a fresh `/proc` (its PID namespace) and `/sys` (its net namespace; the node's sysfs would show the root's interfaces and counters), a tmpfs over `/run` with `/run/thinkpol` owned by the worker (netcfg's lock dir, so the worker's own configurator works after the drop); drops the bounding set to `worker.Capabilities` (NET_ADMIN, NET_BIND_SERVICE), keeps them across `setresuid` to `UIDBase+slot` (default 0x74700000+n, uid = gid, no passwd entry needed), clears inheritable/ambient, sets `no_new_privs`, re-arms the parent-death signal, and reads `/proc/self/status` back. Every credential step runs on all runtime threads (`syscall.AllThreadsSyscall`, `syscall.Set*id`), which needs CGO off (the default build). After the drop the process is non-dumpable, so another worker (another uid) can't ptrace or signal it, and its PID namespace can't name any other process.
- NET_ADMIN opens the namespace's own `/proc/sys/net` (kernel `net_ctl_permissions`), so the data plane sets its own net sysctls (forwarding, etc.); other sysctls stay read-only.

**IPC protocol** (`internal/agent/ipc`): an unnamed `AF_UNIX SOCK_SEQPACKET` pair per worker incarnation; the worker's end is fd 3 (`ipc.WorkerFD`). One packet = one message: `Kind` byte + payload, ≤ `MaxMessageSize` (64 KiB), ≤ `MaxFiles` (4) descriptors via `SCM_RIGHTS` (received with close-on-exec). `Conn.Send` is concurrency-safe; `Receive` is one reader; EOF = the other side is gone. Messages today: `Init` (supervisor → worker, JSON `ipc.Init{Space, Interface, Addrs, Gateways, UID, GID}`), `Ready` (worker → supervisor, after the sandbox), `Stop` (supervisor → worker; exit 0). Unknown kinds are errors (both ends are one build): a worker that sends one is given `StopTimeout` and then killed, and restarts.

**Namespace and veth layout** (slot n, stable while a space is served, reused after): root `tp-space<n>` 169.254.100.(4n+1)/30 and fd74:7073:7061:n::1/64 (set directly with netlink, `IFA_F_NODAD`; the supervisor created the link, so everything on it is its own, and a shared root configurator would couple spaces: one missing interface fails every Apply); space `veth0` .(4n+2)/30 and ::2/64, `lo` up, default routes v4/v6 via the root end, through `netcfg.NewInNamespace("/proc/self/fd/<nsfd>", OwnerSupervisor)` (routes tagged 85, so the worker's `OwnerOverlay` gets `ErrConflict` instead of clobbering them). Transit prefixes are `Options.TransitIPv4` (default 169.254.100.0/22: link-local, clear of 100.64.0.0/10 overlays and 169.254.169.254) and `TransitIPv6` (default fd74:7073:7061::/48); room for 256 workers by default. Link-local IPv4 sources forward and masquerade like any other on Linux.

**Root-namespace isolation**: nftables `table inet thinkpol-supervisor` (google/nftables, pure Go; replaced atomically on start, deleted on Close; nothing else touched). `forward`: `iifname "tp-space*" drop`, `oifname "tp-space*" drop`. `input`: from `tp-space*`, accept `ct state established,related` and ICMPv6 neighbour solicitation/advertisement, drop the rest. A worker has NET_ADMIN in its namespace and can route anything at its veth, so this is what keeps spaces apart, not their routes.

**Logs (S2)**: `internal/agent/logring.Ring`: bounded, line-oriented `io.Writer` (lines cut at 4 KiB, oldest dropped, `Dropped()` counted), safe for slog handlers and child output. The supervisor's own events go to `Options.Log` (discarded by default); worker output goes to one ring per space. Nothing touches a disk.

**For downstream tickets:**
- **TP-010** (shared listener): the supervisor owns the listeners (root namespace). Add kinds to `ipc` (e.g. `KindDatagram` both ways with a flow header; `KindStream` with the conn's fd + consumed bytes as payload; `ipc.Conn` already passes descriptors and is tested with a pipe). Worker side: extend `worker.Run`'s reader (today only `Stop` is legal after Init) to dispatch them to the data plane, and hand `serve` a way to receive them (a `net.PacketConn` over the socket for `udp.Transport.ListenOn`). Supervisor side: `run`'s `read` loop is where worker → supervisor datagrams arrive; fair share is charged after the worker accepts. An incarnation's socket dies with it: the listener must route to the current incarnation (look it up per message, drop while a space restarts).
- **TP-011** (`thinkpol up`): build `supervisor.New(Options{Log: slog over a logring.Ring})` and `SetSpaces` from the node's maps; pass the worker its map section and keys over the socket (add a kind; big payloads as a sealed memfd descriptor, never a file the worker reads: the worker can't read the state dir as its own user, and shouldn't); replace `worker.Idle` in `cmd/thinkpol/worker.go` with the data plane. `Close` on SIGTERM leaves nothing behind (tested).
- **TP-014** (egress): masquerade in the root namespace with `oifname` the uplink and `iifname "tp-space*"`; add the accepts to the supervisor's table (`TableName`, chain `forward`) ahead of its drops (or rebuild it in `installIsolation`), including `ct state established,related` back to the spaces. Workers' outgoing transport dials to other nodes also leave through the veth, so they need the same forward + masquerade, not only member egress. Forwarding inside the space's namespace is the worker's own sysctl (NET_ADMIN allows it). Keep spaces off 169.254.169.254 and the node's own addresses (the input chain already drops those).
- **TP-040** (hosting grants): `SetSpaces` adds/removes guest workers without touching others; caps could be tc on `tp-space<n>` (per-slot link name is in `WorkerInfo.Link`).
- **TP-041** (telemetry): worker output already stays in memory per space (`Output`); a guest's worker output is readable by the node owner's supervisor, so keep anything space-private out of plain logs (sealed telemetry instead).
- **TP-008** (TUN): checked here that a sandboxed worker can create a TUN (`wireguard-go/tun.CreateTUN`), address it with netlink and bind :53; `netcfg.New(OwnerOverlay)` works in the worker (private `/run/thinkpol`).
- **Gotcha found:** vishvananda/netlink 1.3 returns `ErrDumpInterrupted` when a dump races a change; netcfg already retries, and so do the supervisor's stale-link sweep and the tests (one flake in ~30 runs, a link dump during a dead supervisor's veths going away). Any new list call near namespaces being destroyed needs the same.
- Lab note: tests inspect workers from outside only through `/proc/<pid>/status` (lab nodes lack CAP_SYS_PTRACE, so `/proc/<pid>/ns/*` of a dropped worker is closed to root); the test binary doubles as worker in probe mode, reporting its view on stdout/stderr, which the supervisor's ring captures.

## Review findings
Two reviewers; accepted by the orchestrator as decided.

Blockers:
- [ ] B1 netnsid escape: the worker keeps CAP_NET_ADMIN in the initial user namespace and can act on root-namespace links through the veth's link-netnsid. Start the worker in a new user namespace (uid/gid maps; net, mount, pid, ipc, uts, cgroup namespaces created inside it) so NET_ADMIN applies only there. Verify in the lab: before the fix a target-netnsid operation succeeds, after it fails; keep that as a permanent probe. If the lab blocks user namespaces, adjust only the lab node spec for agent tests (documented), never the product.
- [ ] B2 Conntrack bypass: per-space anti-spoof (drop from tp-spaceN unless the source is that slot's transit address, v4/v6), before any accept; per-space conntrack zones (raw prerouting/output `ct zone set`). Test: a spoofed source matching a root flow is not delivered; forged ICMP "related" errors are dropped.
- [ ] B3 Close vs SetSpaces race: Close marks closed, then takes setMu and waits for in-flight stops before removing the table and releasing the lock. Tested.

Should-fix:
- [ ] 4 Neighbour-table flood: permanent neighbour entries on both ends; drop ARP/ND from spaces except what's needed (or restrict source + rate limit). Test an ND flood doesn't fill the root table.
- [ ] 5 logring: a real ring (head index, amortised compaction); test with a "\n" flood.
- [ ] 6 Filesystem/IPC: pivot_root into a minimal tmpfs root (dev/null, zero, urandom, net/tun; fresh proc, ro sys, tmpfs run/tmp); new IPC, UTS, cgroup namespaces; probe asserts `/` contents and that SysV shm isn't shared. Fix DESIGN.md wording (uid per slot, not per space, or uids per space if cheap).
- [ ] 7 Setsid; cmd.Dir "/"; the worker closes every descriptor above its sockets first thing.
- [ ] 8 Resources: a cgroup v2 per worker (pids.max, memory.max; configurable defaults) via UseCgroupFD where available; rlimits as fallback; documented.
- [ ] 9 Open the worker's netns before Wait can reap it.
- [ ] 10 Backoff validation (ResetAfter > 0); unwire/EEXIST self-heal: delete a stale tp-spaceN of any link type, then add; stale non-veth links handled.
- [ ] 11 IPC split: fd 3 control, fd 4 data; non-blocking `TrySend` with ErrFull and a drop counter for data; control never queued behind data. TP-010 note: recvmmsg/sendmmsg batching and pooled buffers first; acceptance ≥ 50 Mbit/s through the shared listener on a lab node pinned to one CPU; fast paths later.
- [ ] 12 `SetSpaces([]Space{ID, Config, Egress, ...})`: the supervisor holds per-space config and sends it to every incarnation after Init (KindConfig; sealed memfd for large payloads) and to the running worker on change. Init carries a protocol version; refuse on mismatch.
- [ ] 13 Egress design in the supervisor (owner of the table): `Egress{Uplink, IPv4, IPv6}` per space; forward accepts after anti-spoof, replies back by zone, root masquerade only of transit ranges; the worker SNATs overlay → its transit address. Implement the table generation if small, otherwise precise TP-014 Notes (other tables' drops still win; IPv6 forwarding needs accept_ra=2 on RA-configured uplinks). Fix DESIGN.md "masqueraded once".
- [ ] 14 TP-040 notes: caps = token bucket at the supervisor's forwarding point (TP-010) + veth limits for egress; per-worker cgroups.
- [ ] 15 Observability: WorkerInfo StartedAt, ReadyAt, NextStart, OutputDropped; renderers (TP-022/TP-042) must sanitize worker output.
- [ ] 16 Device mode (TP-011 notes): compose the data plane in internal/agent (e.g. agent.RunDataPlane(ctx, SpaceConfig, Inbound)); worker.Run adapts IPC; device mode passes real dialers; depguard: internal/dataplane must not import internal/agent.
- [ ] 17 Tests: automated nftables negative control; unknown kind → worker killed and restarted; StopTimeout → SIGKILL; ReadyTimeout; worker exits on socket EOF alone; bounded dump retries in tests.

Nits:
- [ ] close the socket before awaitExit on a protocol error; uid base outside SSSD's default range (picked, documented); close received fds asynchronously; address arithmetic without math/big; DESIGN layout lists agent/ipc, agent/logring; remove own netcfg lock file on Close (if netcfg allows); TP-044 note: a self-update re-exec restarts every worker, health = every worker Ready.

## Log
- 2026-10-10 created in backlog
- 2026-10-10 backlog → in-progress — owner: agent-tp-009, branch: tp-009-agent-supervisor
- 2026-10-10 in-progress → review — make lint, make test green; lab-gotest (internal/agent/...) green 5 runs in a row; labctl gotest ./... green
- 2026-10-11 review → has-errors — two reviews: 3 blockers (netnsid escape, conntrack bypass, Close race), should-fixes 4–17, nits
- 2026-10-11 has-errors → in-progress — owner: agent-tp-009, fixing the review findings
