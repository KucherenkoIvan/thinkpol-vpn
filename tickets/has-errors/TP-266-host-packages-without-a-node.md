---
id: TP-266
title: "Packages that need no root or namespace run their tests on the host, not in a lab node"
milestone: M2
area: lab
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: "agent-tp-266"
branch: "tp-266-host-packages"
---

## Goal
The node phase (`labctl gotest ./...`) runs every package's tests in a lab node. packettest and path never need root or a namespace (no test reads `THINKPOL_LAB`), yet each costs a container start and a lab slot on every cold run, for 0–13 s of tests (TP-263). Running such packages as plain host `go test`, cached by Go's own test cache, saves those starts.

## Scope
- Decide per package (build tags or a marker) which need a node; the rest run as host `go test` in `make lab-test`'s node phase or in `make test`, keeping what they prove.
- Candidates on rewrite c4c4b779 (no test file reads `THINKPOL_LAB`, `Geteuid` or a netns; to confirm per package): internal/agent/ipc, internal/agent/logring, internal/agent/worker, internal/dataplane/blobs, internal/dataplane/checksum, internal/dataplane/ifbind, internal/dataplane/packettest, internal/dataplane/path, internal/dataplane/rules, internal/dataplane/transport, internal/dataplane/transport/memory, internal/dataplane/transport/transporttest, internal/dataplane/trusteddir, internal/dataplane/wg, internal/devmap, internal/lists, internal/netmap, internal/shaping, lab/ip.

## Acceptance
- [x] List of packages moved, with why each needs no node.
- [x] Node-phase lab starts before/after, in Notes.
- [x] Every moved package still runs in make lab-test (or make test) and passes.

## Notes
**Mechanism.** A package whose tests need no node carries `hosttests_test.go` (`lab.HostTestsFile`): the package clause and a comment saying why. `labctl gotest` (lab/labctl/main.go `nodePhase`) runs such packages on a Linux machine under one `go test -json` beside the labs (`lab.GoTestOnHost`, lab/gotesthost.go), as the user, with `THINKPOL_LAB` taken out of the environment, cached by go test's own cache; on other machines and with `-perf` they stay in nodes. Two checks keep the mark right: a marked package fails in the node phase when any of its top-level tests skips on the host (a test skipping for want of the lab can't pass unseen), and `TestNodelessPackagesNeedNoNode` (`make test`) fails when a marked package's test files, or a module test helper (`...test`) its tests build with, mention `THINKPOL_LAB`, `Geteuid`/`Getuid`, `Unshare`/`Setns`/`CLONE_NEW`, `nsthread` or `netns`. They all already ran in `make test` on the host; every one was run as a user without `THINKPOL_LAB` on Linux before marking: 268 top-level tests, all passed, none skipped (only the in-memory transport's conformance subtests for features it lacks skip, as they do in a node).

**Moved (18), and why each needs no node:**
- internal/agent/ipc: messages and descriptors over socket pairs the test makes itself.
- internal/agent/logring: rings in memory.
- internal/agent/worker: shared listeners with a recording sender; a worker started without its supervisor's sockets stops before its sandbox (workers themselves are tested through the supervisor, which stays in a node).
- internal/dataplane/blobs: services over a loopback test network (`NewOnNet`), no interface binding.
- internal/dataplane/checksum, packettest, rules, netmap, shaping, lab/ip: computation on bytes and maps in memory.
- internal/dataplane/ifbind: on Linux only the network name's family is tested; nothing binds a socket (the binding test is darwin's).
- internal/dataplane/path: in-memory transports and a channel TUN; its own test keeps the package off sockets.
- internal/dataplane/transport: endpoint, inbox and shaping checks without a socket.
- internal/dataplane/transport/memory, transport/transporttest: the in-memory transport.
- internal/dataplane/wg: WireGuard devices over the in-memory transport and channel TUNs.
- internal/devmap: map plans and key files in the test's own directory.
- internal/lists: list import and matching in memory and the test's directory.

**Kept in a node:** internal/dataplane/trusteddir. Its tests pass as a user, but its ownership check takes another branch as root (`uid != 0 && uid != euid`), and the agent runs as root: only the node run covers that branch.

**Node phase, cold (`LAB_NOCACHE=1`, `labctl gotest -p 12` over `./...`, as make lab-test runs it), both under other runs' load:**
| | lab starts | wall | slot wait summed (median) |
|---|---|---|---|
| before (unchanged tree, 426f2606) | 40 | 1143 s | 9318 s (164 s) |
| after (b886094f) | 22 | 623 s | 3280 s (110 s) |

The 18 packages took 98.8 s summed on the host (slowest transport/memory 41.7 s, netmap 17.5 s, path 14.8 s); in the before run their labs took 12567 s summed of package time. The after run failed transport/memory: the host run counted its skipped conformance subtests, since `go test -json` prints a subtest's result line unindented; fixed in 7be89020 (counts come from test2json's events, top-level tests only), and the full lab below ran it green.

**Full `make lab-test` on 7be89020:** tests passed, over budget (default stream 23m53s > 15m, the same ballpark as the 23m12s cold full lab measured on rewrite cb0348d6; the node phase is off the critical path, TP-263), long stream 4m28s, 1433 s wall including the lock wait. Node phase: 40 packages, 18 of them on the host, 22 labs.

**Out of scope:** the before run (unchanged tree) failed `internal/agent/supervisor` TestWorkersAreSandboxed once: "space 0 has leaked host-file fds: [/proc/748/uid_map]"; it passed in the after run and the full lab.

## Review findings
- [ ] R1.1 (blocker) labctl's hostRunsNodeless checks only the OS and -perf, never root: `sudo make lab-test` (or a CI run as root) runs all 18 marked packages as root in the host's namespaces (worker's sandbox could mount or pivot_root if a future test reaches it). Run the host path only when the effective uid isn't 0 (`hostRunsNodeless(goos, euid, perf)`), else keep them in nodes; a table row for euid 0; make the README's "as the user running it" true.
- [ ] R1.2 (should-fix) the static guard (lab/gotesthost_test.go) reads only the package's _test.go files and helpers named `...test`; it misses production code the tests call, other helpers (e.g. internal/testutil), and terms like Mount, PivotRoot, Chroot, Prctl, CAP_, netlink, nftables, /dev/net/tun, os/exec. Widen it: scan every main-module package in the marked package's `go list -deps -test` (at least its test helpers and the package itself) with the wider term list; keep `make test` green; it is a lint behind R1.1's kernel guard, say so.
- [ ] R1.3 (should-fix, tests that can't fail) add TestTestHelperDirs (wg lists transport/transporttest and packettest, not itself) and a fixture module whose helper mentions THINKPOL_LAB so needsNode fires on a helper; a test for the "go test ended without a result for a package" path (lab/gotesthost.go: deleting the missing loop must fail a test).
- [ ] R1.4 (should-fix) the host `go test` gets no -p (it builds and runs GOMAXPROCS packages beside node builds held to -build-p $(LAB_P)): pass -p from the build concurrency; and CGO_ENABLED=0 like the nodes (the same binaries as nodes and production).
- [ ] R1.5 (should-fix) lab/gotesthost.go keeps all output (=== RUN, --- PASS, passing t.Log: -json is verbose), capped at 8 MiB head-only, so a late failure's text is cut: filter like FilterTestJSON (drop passing output; keep the first and last MiB), and set Cached only from the package-level ok … (cached) line.
- [ ] R1.6 (TP-265) see TP-265's findings.
- [ ] R1.7 (ticket) file nothing; note in the Log that TestWorkersAreSandboxed failed once on the unchanged tree ("leaked host-file fds /proc/…/uid_map") for the orchestrator to track.

## Log
- 2026-11-19 created in backlog (TP-263)
- 2026-11-19 backlog → in-progress, owner: agent-tp-266
- 2026-11-19 implemented (with TP-265, same branch): hosttests_test.go mark on 18 packages, lab.GoTestOnHost, labctl nodePhase; TestNodelessPackagesNeedNoNode, TestListGoPackagesFindsTheHostTestsMark, TestGoTestOnHost, TestHostRunReadsGoTestJSON, TestHostOutputBounded, TestGotestRunsNodelessPackagesOnTheHost, TestHostRunsNodeless
- 2026-11-19 mutations, each killed: M1 hosttests_test.go added to internal/dataplane/tun (TestNodelessPackagesNeedNoNode: tun_linux_test.go and the nsthreadtest helper flagged); M2 a host skip doesn't fail the package; M3 THINKPOL_LAB kept in the host env; M4 the mark not detected; M5 labctl ignores nodelessOnHost (docker called); M6 perf runs host packages; M7 a cached host package timed; M14 host tally from output lines (subtest skip fails the package)
- 2026-11-19 node phase cold before/after: 40 → 22 lab starts, 1143 s → 623 s wall (both under load); make lint, make test green on 7be89020; make lab-gotest PKG=transport/memory + trusteddir green on 7be89020; full make lab-test on 7be89020: tests passed, over budget 23m53s (as on rewrite), 1433 s wall
- 2026-11-19 in-progress → review
- 2026-11-19 review → has-errors
- 2026-11-19 review round 1: fix R1.1–R1.7
