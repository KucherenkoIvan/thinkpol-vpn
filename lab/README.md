# The lab

Docker containers on separate networks, driven by Go tests: the censor lab of [lab.md](../docs/design/lab.md#censor-lab) and the place where every Linux networking test runs. All it needs is Docker 27 or later (with Compose v2) and Go; nothing in the lab touches the host's network stack.

```sh
make lab-test     # lab tests and every package's tests inside a lab node, at once, then tear down
make lab          # the same, ending in the censor matrix: lab/RESULTS.md
make lab-gotest PKG=./internal/dataplane/netcfg/... RUN=TestRoutes   # one package, in a node (COUNT=n repeats; fails if all skip)
make lab-up       # the standard topology for poking around (prints addresses)
make lab-down     # remove every lab this checkout started
make lab-perf     # performance gates, alone on the host (see "Performance gates")
```

**Censor modules** are `lab/censor`'s (its package doc lists them and how they compose); the matrix runs every transport against each, one module per cell, and new ones join it as a row of `censorCases` in `results_test.go`. `ip-blocklist` and `sni-blocklist` block listed addresses (either end) and the names a ClientHello asks for (read from the reassembled stream, so a ClientHello split over segments or TLS records is read whole); `wireguard-fingerprint` and `openvpn-fingerprint` block WireGuard's messages by type and size and OpenVPN's handshake by its opcodes, on any port. Besides the transports, the matrix has control rows (plain TCP, and HTTPS to a site no list names) and reference rows: real kernel WireGuard and OpenVPN over UDP and TCP between device-a and server-1, one tunnel per underlay family, whose handshakes start in the probe, after censord is up, so the fingerprints see them from the first packet. The `reality` row runs in `lab.Upstream()`: server-1 serves reality through its shared listener (`thinkpol up -mode server`, from `lab/maps/reality.yaml`), its target the camouflage site, and device-a comes up in the probe, after censord, so the censor reads its TLS connection from the first byte. `wireguard-rhythm` blocks a TLS connection whose records show WireGuard's rhythm: an exchange that stands out (not seen in the rekey period before it, or after a quiet band) three times in a row, each 2 to 3.5 minutes after the one before, or a steady run of unanswered idle records; it reads recurrence from the records alone, so a cell against it says something only when its probe runs long enough for three rekeys (up to 7 minutes, up to about 10 minutes when batched) or three idle keepalives. The reality row's cell against it keeps its tunnel in use for 7.5 minutes first (a ping every 2 s, the transport's default settings), fails if the module blocked the connection meanwhile, and is an error if the module couldn't frame it. `fully-encrypted` blocks a connection whose client's first data looks random by Wu et al.'s exemptions (set bits per byte, printable bytes, a TLS or HTTP start), UDP's first datagram too; the `random-tcp` reference row, a naive echo server fed random bytes, is what it and the prober must block. `prober` probes the server of a suspect TCP connection from the router (replayed and random bytes, and a TLS handshake of its own when the connection names the camouflage site, as the https row's does) and compares every answer with nginx's on the camouflage node, and flags the upstream tell (or only reports it, `upstreamTell: "report"`); the `relay-tcp` reference row, server-1 splicing every connection to the camouflage site as REALITY does with what it doesn't recognize, runs in `lab.Upstream()` in every cell and is what the tell must block; `server-hello` compares a connection's ServerHello (JA3S, JA4S, extensions, ALPN) with the camouflage site's answer to the same ClientHello. Those two run in `lab.Upstream()`, and their cells probe twice, scoring the probe after the module's verdicts, since an active module judges a connection only after it has crossed.

**M0 acceptance** (device ↔ server and relayed device ↔ device pings, the relay proof, no WireGuard at the router) is `TestM0`; what it runs and proves is in [M0.md](M0.md).

## How it is built

- **One image**, `lab/Dockerfile`: Debian slim, pinned by digest, with iproute2, nftables, iputils, tcpdump, curl, wireguard-tools (`wg`; kernel WireGuard for the matrix's reference row), openvpn (the other reference VPN), openssl (`s_server` as a TLS target), nginx (pinned: the camouflage site and the https row's server), netcat, socat (the random-tcp row's echo server), the lab CA and the camouflage site's certificate (see "The standard topology"), and dbus-daemon with systemd-resolved (installed, never started by the image: a test that needs a device resolving through resolved starts both). It is tagged with a hash of the Dockerfile and the platform, so checkouts share it and a changed Dockerfile builds a new tag (one build per tag, serialized host-wide by a lock file next to the slot locks; the first build takes about a minute).
- **No Go inside.** `thinkpol`, and the lab's own tools (`labdns`, a stand-in for resolvers out in the world that answers every name with fixed addresses and prints who asked what; with `-server` and `-query`, asks one resolver one A question and prints the reply's rcode (with ` aa` when authoritative); `censord`, the censor of [lab.md](../docs/design/lab.md#censor-lab), run in the router), are cross-compiled on the host (`GOOS=linux CGO_ENABLED=0`, `GOARCH` of the Docker server, override with `THINKPOL_LAB_GOARCH`) into the run's own binary directory, which every node of the run mounts read-only at `/opt/thinkpol/bin` (on `PATH`). The checkout is mounted read-only at `/src` for test data.
- **Binaries per run.** Each process that starts labs (a `go test` binary of `lab/`, `labctl gotest`) builds once into `lab/bin/run-*`, a directory of its own, so two runs from one checkout never rebuild a binary the other's containers are running. The run removes it when it ends, and `lab/bin` goes with the last one; every test package that starts labs calls `lab.Main(m)` from its `TestMain` for that, and a lab test in a package without it fails. A run that dies first (Ctrl-C, SIGKILL, a test binary's `-timeout`) leaves its directory unlocked: the next run from the checkout, `make lab-down`, and the end of `make lab-test` (unless `THINKPOL_LAB_KEEP` is set) remove it. With `THINKPOL_LAB_KEEP` set, a run lists every lab it starts in its directory's `.kept`; a lab kept for a failed test (or left up by a run that died) keeps the directory, and only `make lab-down` (or `labctl down -tests`, or a later `make lab-test`'s clean-up) removes it, once none of the labs it lists is up: a kept lab another run's clean-up skips, or one Docker failed to remove, keeps its binaries. One gap is accepted: if a run dies while its `docker compose up` is still creating a kept lab, and `make lab-down` asks Docker before that lab exists, the directory goes and the lab comes up without binaries. `make lab-up`'s lab outlives `labctl`, so its binaries live in its own `lab/.run/<project>/bin` and go with the lab.
- **Every node** runs as root with `NET_ADMIN`, `NET_RAW` and `SYS_ADMIN`, `/dev/net/tun`, AppArmor off (its Docker profile blocks the mounts network namespaces need), and the seccomp profile `lab/seccomp.json`: Docker's default plus one rule allowing `pivot_root` with `SYS_ADMIN`, which every worker sandbox needs and the default denies even then. `make lab-seccomp` generates it (`lab/seccompgen`) from `github.com/moby/profiles/seccomp` v0.2.4, the version Docker 29.9.3 vendors; the file is committed, so a lab run needs neither the network nor the generator. The generator is a module of its own so the product's `go.mod` doesn't depend on moby/profiles. To follow a newer Docker, raise the version in `lab/seccompgen/go.mod`, run `make lab-seccomp` and update the version here; `TestSeccompProfileAllowsPivotRootOnlyWithSysAdmin` pins what the profile allows of `mount`, `unshare`, `setns`, `bpf`, `clone3`, `keyctl`, `ptrace` and `pivot_root`, so a new default that changes those fails it until someone looks. Docker Desktop runs containers without seccomp, so only a Linux host shows the denial; declaring the profile gives the nodes the same one on both. That covers namespaces, TUN, nftables (queue rules included) and network sysctls: `/proc/sys/net` is writable, the rest of `/proc/sys` is not. Nodes are **not privileged**; `NodeSpec.Privileged` exists for a need these can't meet, with the reason written next to it. Each node has `THINKPOL_LAB=1` and `LAB_NODE=<name>` in its environment and runs `sleep infinity` under an init unless the topology says otherwise.
- **The lab is sealed.** Before a node's own `Command` runs (it waits for a marker the harness writes last), the harness, in every node: deletes Docker's default routes (a node with a `Gateway` routes IPv4 and IPv6 through it instead); cuts the node off from Docker's bridge, the Docker VM's end of every lab network and the only way out: its addresses are blackholed and an nftables `netdev` table per interface (`tplab_<interface>`) drops every frame to or from its MAC, which also covers its IPv6 link-local address (published ports of other projects listen in the VM); points `/etc/resolv.conf` at nothing (lab names resolve through `/etc/hosts`, which lists every node); and the networks don't masquerade. Docker's own resolver, still at `127.0.0.11` for anything that asks it directly, forwards a name it doesn't know to the node's nameserver, `lab.DeadEndNameserver` (198.18.0.53, in the benchmarking range no lab network or test uses), from the node itself, so the sealing stops the forward. Without it Docker forwards to the host's nameservers from the host's network namespace, which no sealing reaches: Docker 29 does that for every nameserver in the host's resolv.conf, Docker 27 for loopback ones such as systemd-resolved's. A lab node can reach other lab nodes and nothing else, which `TestSmoke/hermetic` checks. Tests must not delete the `tplab_*` tables (no `nft flush ruleset` in a node: flush your own tables).
- **Topologies are declared in Go** and rendered to a Compose file under `lab/.run/<project>/` (ignored by git). There is no shared `compose.yaml` to edit: a test that needs another node declares it.

## The standard topology

```
device-a, device-b ── [devices] ── router ── [servers] ── server-1, server-2, internet
```

`lab.Standard()`: networks `devices` and `servers` (dual-stack), the `router` on both with forwarding on, devices and servers routing through it, `internet` (the target for egress and "direct" traffic) on the servers side. Servers have forwarding on too (relays, exits). Everything between the two sides crosses the router: that is where packets are captured, and where the censor sits. The censor reads each TCP connection as a Linux receiver would (what it still reads differently, and so what evades it, is in the Limits of `lab/censor`'s package doc).

`lab.Upstream()` adds a `camouflage` node on a network of its own, `world`, joined by the router: a server's connection to it crosses the router too, where the censor sees it (the prober's upstream tell, [lab.md](../docs/design/lab.md#censor-lab)). `lab.StartCamouflage(t, l)` runs the camouflage site there: nginx, TLS 1.2 and 1.3, HTTP/2 and HTTP/1.1, on port 443 of both its addresses, with a certificate for `camouflage.example.net` (and `www.example.net`) signed by the lab CA. The image makes the lab CA when it is built and puts it in the system roots, so every node verifies the site as it would a real one: a reality listener's certificate check passes, and REALITY's own detection learns the site's post-handshake records. It is the target reality's listener splices to, and the site the prober and the server-hello comparison point at (the matrix's cases start it with `lab.StartCamouflage` too).

## Writing a lab test

Lab tests drive containers from the host, so they need Docker: put them in `lab/` behind the `lab` build tag. `make test` doesn't run them; `make lab-test` does. Every test gets its own lab, torn down when it ends, so tests can be `t.Parallel()`.

```go
//go:build lab

package lab_test

func TestRelayPing(t *testing.T) {
	t.Parallel()
	l := lab.Start(t, lab.Standard())
	dev, srv := l.Node(lab.DeviceA), l.Node(lab.Server1)

	srv.WriteFile(t, "/etc/thinkpol/map.bin", mapBytes)
	srv.Start(t, "thinkpol", "up", "--map", "/etc/thinkpol/map.bin") // stopped at the end
	dev.MustExec(t, "ping", "-c", "1", srv.IPv6(lab.NetServers).String())
}
```

- **Nodes:** `l.Node(name)` gives `IPv4(network)`, `IPv6(network)`, `Interface(network)` (eth0, …), `Exec(ctx, args...)` (a non-zero exit is an error, `Result` has stdout, stderr and the code), `MustExec(t, args...)` (returns stdout), `WriteFile(t, path, data)`, `Start(t, args...)` for background processes (`Stop`, `Done`, `Output`; their output goes to the test log on failure), and `ExportFS(ctx, w)`, the node's filesystem as a tar stream (what a node leaves on disk).
- **systemd:** a node with `Systemd: true` runs systemd as its PID 1 (unprivileged: its own cgroup namespace, made writable before systemd starts; `/run` a tmpfs; systemd-resolved, systemd-networkd and nginx masked), for tests of the service (`thinkpol service install`). `WaitBooted(ctx)` waits for its boot; `Restart(ctx)` is a reboot: the node seals itself again before systemd starts (its sealing script is kept in `/etc/lab/seal.sh`), and Restart checks it did (its addresses, frame filters, blackholed bridges, default routes), and `/run` is fresh, though the kernel's boot id is the Docker VM's and stays. Processes `Start` ran in it are gone after a restart.
- **Files and disks:** tests read and write nodes' files through these helpers only. They never touch block devices or the Docker VM's disks, and never write to `/src` or `/opt/thinkpol/bin`: the `:ro` mounts don't stop root with `SYS_ADMIN` from remounting them, and they are the checkout.
- **Waiting:** `lab.Eventually(t, timeout, func() error)` polls until nil.
- **Failing tests** print the containers' logs. With `THINKPOL_LAB_KEEP=1` a failed test's lab stays up for inspection (`docker compose -p <project> exec <node> bash`, the project is in the log); `make lab-down` removes it.

### Adding a node or a network

Declare it in the test, never in a shared file:

```go
topo := lab.Standard().With(
	lab.NodeSpec{Name: "server-3", Networks: []string{lab.NetServers}, Gateway: lab.Router, Forward: true},
)
// or a network of its own, joined by the router:
topo = topo.WithNetworks(lab.Network{Name: "mobile", IPv4Only: true}).With(
	lab.NodeSpec{Name: lab.Router, Networks: []string{lab.NetDevices, lab.NetServers, "mobile"}, Forward: true},
	lab.NodeSpec{Name: "phone", Networks: []string{"mobile"}, Gateway: lab.Router},
)
```

`With` replaces a node of the same name, so the second call above re-declares the router on three networks. A topology from scratch is just a `lab.Topology{Networks: ..., Nodes: ...}`. A node can have a `Command` (its main process) and `Env`. Only the gateway's default route is set up; anything more (a second router, static routes) the test does with `MustExec(t, "ip", "route", ...)`.

### Capturing packets

```go
c := l.Node(lab.Router).Capture(t, "udp")          // tcpdump filter, "" for everything
// ... traffic ...
p := c.WaitFor(t, 5*time.Second, func(p lab.Packet) bool { return p.DstPort == 51820 })
all := c.Stop()                                      // every packet; also stopped at the end
```

A `Packet` has `Src`, `Dst`, `Proto`, `SrcPort`, `DstPort`, `Payload` (after the TCP/UDP header; the whole message for ICMP), the whole `IP` packet, and where it was seen: `Network` (the lab network of the interface, "" for one the lab didn't create, e.g. a TUN) and `Outgoing`. Capture returns once tcpdump is listening, so nothing sent after it is missed. `Complete()` stops the capture and errors if tcpdump reported packets dropped by the kernel or interface (or no statistics at all); a capture's clean-up fails the test the same way, and a check that something is *absent* from a capture should call `Complete` first.

The router sees each forwarded packet **twice**: arriving (`Network: "devices", Outgoing: false`) and leaving (`"servers"`, `Outgoing: true`); filter on one side when counting. Capture works on any node, not only the router.

## Tests that run inside a node

Unit tests that need root, network namespaces, netlink, nftables or a TUN live next to their code, with the usual guard:

```go
if os.Getenv("THINKPOL_LAB") == "" {
	t.Skip("needs the lab")
}
```

`make lab-test` compiles **every** package's tests for Linux and runs each package, as root, in a fresh lab node of its own with `THINKPOL_LAB=1` (working directory: the package's directory under `/src`), so these tests run there and skip everywhere else. The node is alone on one dual-stack network with no route out: tests create the namespaces, veths and TUNs they need. Packages run four at a time (`labctl gotest -p`, `make lab-test LAB_P=n`), each binary with `-test.timeout=10m` unless given its own. For one package: `make lab-gotest PKG=./internal/... RUN=regexp`. From a lab test, `node.RunGoTests(t, "./internal/agent/...", "-test.run", "X")` runs packages inside any node of a topology (that node, not a fresh one).

`make lab-gotest` takes any package pattern, `./lab/...` included. It runs the tests each package has without the `lab` build tag in a fresh node, as above. Then, for every package with tests behind the tag (today `./lab` and `./lab/prototypes/reality`), it runs `go test -tags lab` for that package on the host, the way `make lab-test`'s `lab/` phase does (`labctl gotest -tagged`, timeout `60m` unless given). Those are lab tests: they start their own labs and run in-node tests there. A node can't run them, since it has no Docker; without the host run they would not be compiled in, and in-node tests that need one of them to set things up (`TestRealityClientInterop` needs `TestRealityPrototype`, the reality transport's `TestStockXray` needs `./lab`'s `TestRealityStockXray`) only skip. `make lab-gotest` fails a package in which tests ran and every one skipped, counting both runs, and fails a run in which no test ran at all (`labctl gotest -fail-skipped`, which implies `-v`). A warning would scroll past in the output while the exit status stayed green, and that green status is what a ticket cites as evidence. `RUN` applies to both runs; a package where `RUN` matches nothing is not a failure as long as some other package ran a test. An in-node test that a lab test runs is reached through that lab test: `RUN=TestRealityClientInterop` alone only skips it twice and fails, `RUN=TestRealityPrototype` runs it. `make lab-test` passes neither flag: its `lab/` phase already runs the lab tests, and its node phase over `./...` includes packages whose tests skip in a bare node by design. That is also why `make lab-gotest` needs `PKG` and stops with an error without one: over `./...` it would fail by design and run every lab test on the host under one time limit. `make lab-test` is the target that runs everything.

## Tests under load

Several agents run `make lab-test` at once, so every test runs on a busy machine: a goroutine, a tcpdump or a whole node can be held up for hundreds of milliseconds. A test that passes only on an idle machine is a broken test. What holds up:

- **Synchronize, don't sleep.** Wait for the event itself (a counter, a log line, a kernel flag, a channel), with a generous deadline; a fixed sleep before an assertion is a race. Sleeps are fine only for "nothing happens" windows, which load can only make pass.
- **Lossy paths retransmit or count.** UDP over loopback or a lab network drops a datagram when its reader is held up and the socket buffer fills. A ping-pong resends after a timeout, a burst goes in batches the receiver has room for, and an exact count comes from the protocol's own counters, not from packets that crossed a socket.
- **Time bounds prove a mechanism, not a speed.** Bound an elapsed time only to tell two mechanisms apart (a retry on the test's interval versus the default one), with the bound far from both.
- **Performance belongs to `make lab-perf`** (below): throughput, loss under load and latency targets. `make lab-test` keeps a check of the same path that load can't change.
- **Statistical checks** state their false-failure probability in a comment; keep it negligible (one in tens of millions of runs, or rarer).
- **Captures** have a ring of about 500 frames: pace what you send, and filter to one side of a router (`outbound`) when you count.

`make lab-test` runs its two phases **at the same time**: the `lab/` tests and the in-node packages, each phase's output prefixed (`[lab]`, `[node]`), one exit status for both, the tear-down after both. Both phases draw lab slots from the same cap, so a concurrent run competes with all of this run's labs at once.

`make lab-test` runs `LAB_P` (default 4) packages in nodes at once and doesn't lower that when the host is busy. The load that matters comes from other runs, which a run can't control, and the Docker VM's load isn't the host's load average. The lab slot cap (`THINKPOL_LAB_MAX_LABS`) bounds the labs all runs start together. When another lab run is already going, pass `make lab-test LAB_P=1`: two full-parallel runs multiply each other's labs and CPU. `LAB_P=1` only throttles the node phase, though: the `lab/` tests are bounded by `go test -parallel` and the lab slot cap, not by `LAB_P`. On a quiet machine leave the default. The `lab/` phase has `LAB_TIMEOUT` (default `60m`, as `make lab-gotest COUNT=…` has) for its `go test`: its censor matrix alone has taken 21 minutes on a slower host, and a hung run only costs that cap.

`labctl gotest -count n` (`make lab-gotest PKG=... RUN=... COUNT=n`) repeats tests in one node, and the package's lab tests on the host, to show a fix holds.

## Performance gates

Throughput targets (PRD Performance) depend on what else the Docker VM is doing, so `make lab-test` doesn't gate on them: a perf test there checks only that the path works, in a way load can't change (flow-controlled, so nothing may be lost), and doesn't measure. `make lab-perf` runs the gates: `labctl gotest -perf` waits until no other lab of any run sharing this `TMPDIR` holds a slot, keeps new ones from starting while it runs (every lab slot holds `perf.lock` shared, a perf run holds it exclusively; its own labs don't wait), and sets `THINKPOL_LAB_PERF=1` in the node. A gated test measures once and, if it misses a target, twice more, and fails on the median of the three.

A perf test checks `THINKPOL_LAB_PERF` itself (packages under `internal/` can't import `lab`), is named `Test…Throughput`, and its package is listed in the Makefile's `LAB_PERF_PKGS`. Today that is `TestSharedListenerThroughput` (`internal/agent/supervisor`): under 0.5% loss at 100 Mbit/s and at least 50 Mbit/s one way and echoed, all on one CPU; in `make lab-test` it sends 2000 echoes through the handoff with at most 32 in flight, which no queue on the path can overflow, and every one must come back. The lock doesn't see labs from `make lab-up` once `labctl` has exited, runs with another `TMPDIR`, or other projects on the Docker VM; a busy host can also keep a perf run waiting.

## Isolation and safety

- **Names.** Every lab is a Compose project named `tplab-<checkout>-<hash of its path>` for `make lab-up`, plus `-t-<run>-<test>-<hash>` for a test's lab and `-gotest-<run>-<hash of the package>` for in-node tests (`go run ./lab/labctl project` prints the prefix). `<run>` is the run's id: `make lab-test` gives both its phases one (`THINKPOL_LAB_RUN`, from `labctl run-id`), and any other process that starts labs (a `go test` of `lab/`, `make lab-gotest`) makes up its own, so two runs from one checkout never share a lab's name. `THINKPOL_LAB_PROJECT` replaces the checkout part (`[a-z0-9][a-z0-9-]*`, at most 40 characters), never the `tplab-` prefix. No container names are fixed.
- **Ownership is the checkout's path, not the name.** Every lab container and network is labelled `org.thinkpol.lab=1` and `org.thinkpol.lab.root=<checkout path>`. `make lab-down` and the clean-ups find labs by those labels, and remove a project only if its name starts with `tplab-` and every container and network in it carries `org.thinkpol.lab=1` and exactly this checkout's path. Volumes are never removed (the lab has none). Starting a lab under a name this checkout already uses replaces the old lab; under a name another checkout's lab uses (two checkouts with the same `THINKPOL_LAB_PROJECT`), it fails instead, and neither checkout can remove the other's labs.
- **Compose sees only the lab.** Tear-down runs `docker compose` from an empty directory with no `COMPOSE_*` variables, so no compose file or setting of anyone else's is ever loaded.
- **Subnets.** Each lab network gets a /24 from `172.16.0.0/16` and a /64 from a random unique-local /48. That range is the /16 just below Docker's default address pools (which start at `172.17.0.0/16`), so labs don't use up the addresses other projects on the daemon get; if it clashes with something of yours, set `THINKPOL_LAB_SUBNET_POOL`. The choice is checked against every network on the daemon, serialized host-wide by a lock file, and retried if Docker still reports an overlap.
- **A cap on labs.** At most `THINKPOL_LAB_MAX_LABS` (default 12) slots are held at once by labs from tests and in-node runs. The cap is kept with lock files in the temporary directory, so it is shared by everything that uses the same `TMPDIR` (normally all of one user's runs); runs with different `TMPDIR`s don't see each other's slots. All the labs one top-level test starts share one slot, so a test starting a second lab never waits for itself; a test whose subtests each start one lab (the censor matrix, TestM0) gives each subtest its own slot instead (`lab.StartOwnSlot`). Don't mix the two in one top-level test: a parent holding a `lab.Start` slot while its subtests wait in `lab.StartOwnSlot` can wait on itself. `make lab-up`'s lab doesn't count once `labctl` has exited.
- **Leftovers.** `make lab-test` first removes labs whose checkout no longer exists (`labctl down -stale`), then, at the end, its own run's labs (`labctl down -run <id>`) and the binary directories of this checkout's runs that have ended (unless `THINKPOL_LAB_KEEP` is set). Another run's labs from the checkout stay, running or not; `make lab-down` removes every lab of the checkout, kept ones and leftovers of killed runs included, and `labctl down -tests` every test and gotest lab of it.

Several checkouts, and several runs from one checkout, can run `make lab-test` (or `make lab-gotest`) at once, and `make lab-down` only removes its own checkout's labs.

## Environment

| Variable | Effect |
|---|---|
| `THINKPOL_LAB_PROJECT` | replaces the checkout part of project names |
| `THINKPOL_LAB_RUN` | the run id in test and gotest labs' names (`[a-z0-9]`, at most 8 characters); `make lab-test` sets a fresh one, unset a process makes up its own. Don't export it: a process started from that environment joins the run, sharing its labs' names and its clean-up |
| `THINKPOL_LAB_KEEP` | a failed test's lab stays up; `make lab-test` skips its final clean-up |
| `THINKPOL_LAB_MAX_LABS` | lab slots at once per `TMPDIR` (default 12; one per top-level test, one per subtest for `lab.StartOwnSlot`) |
| `THINKPOL_LAB_SUBNET_POOL` | IPv4 range for lab networks (default `172.16.0.0/16`) |
| `THINKPOL_LAB_PERF` | set to 1 in the nodes by `make lab-perf`; tests check their performance targets only then |
| `THINKPOL_LAB_GOARCH` | architecture to build for (default: the Docker server's) |

## Gotchas

- A run's clean-up removes only its own labs, so the labs a killed run left up (Ctrl-C during `make lab-test` leaks the labs its tests had running) stay until `make lab-down`: another run's clean-up, the next `make lab-test`'s included, leaves them. After an interrupted run, run `make lab-down` (once no other run from the checkout is going: it removes all of the checkout's labs).
- Lab networks are not Docker `internal` networks on purpose: Docker drops forwarded IPv4 between internal networks, which would break the router. The sealing above keeps the lab closed instead.
- Lab networks use Docker's `routed` gateway mode. In the default `nat` mode Docker 28 and later drop, in the host's raw `PREROUTING`, every packet to a container's address that didn't arrive on that container's own bridge; on a host with `br_netfilter` loaded that catches the frames a node sends to the router for a node on another lab network, so nothing crosses the router. `routed` has no such rule and no NAT; Docker 27.0 and later accept it, while `nat-unprotected`, the other mode without that rule, needs 28. The networks also keep `enable_ip_masquerade=false`, redundant with `routed`, as a second guard.
- `getent hosts <node>` prefers IPv6; use `getent ahostsv4` for the IPv4 address.
- The image's tags accumulate as the Dockerfile changes; remove old ones with `docker image rm thinkpol-lab:<tag>`.
