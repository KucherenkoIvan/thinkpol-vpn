# The lab

Docker containers on separate networks, driven by Go tests: the censor lab of [DESIGN.md](../DESIGN.md#censor-lab) and the place where every Linux networking test runs. All it needs is Docker (with Compose v2) and Go; nothing in the lab touches the host's network stack.

```sh
make lab-test     # lab tests + every package's tests inside a lab node, then tear down
make lab          # the same for now; TP-024 turns it into the censor matrix
make lab-gotest PKG=./internal/dataplane/netcfg/... RUN=TestRoutes   # one package, in a node
make lab-up       # the standard topology for poking around (prints addresses)
make lab-down     # remove every lab this checkout started
```

## How it is built

- **One image**, `lab/Dockerfile`: Debian slim, pinned by digest, with iproute2, nftables, iputils, tcpdump, curl, wireguard-tools (`wg`), openssl (`s_server` as a TLS target), nginx-light and netcat. It is tagged with a hash of the Dockerfile and the platform, so checkouts share it and a changed Dockerfile builds a new tag (the first build takes about a minute).
- **No Go inside.** `thinkpol` is cross-compiled on the host (`GOOS=linux CGO_ENABLED=0`, `GOARCH` of the Docker server, override with `THINKPOL_LAB_GOARCH`) into `lab/bin`, which every node mounts read-only at `/opt/thinkpol/bin` (on `PATH`). The checkout is mounted read-only at `/src` for test data.
- **Every node** runs as root with `NET_ADMIN`, `NET_RAW` and `SYS_ADMIN`, `/dev/net/tun`, and AppArmor off (its Docker profile blocks the mounts network namespaces need). That covers namespaces, TUN, nftables (queue rules included) and network sysctls: `/proc/sys/net` is writable, the rest of `/proc/sys` is not. Nodes are **not privileged**; `NodeSpec.Privileged` exists for a need these can't meet, with the reason written next to it. Each node has `THINKPOL_LAB=1` and `LAB_NODE=<name>` in its environment and runs `sleep infinity` under an init unless the topology says otherwise.
- **The lab is sealed.** Before a node's own `Command` runs (it waits for a marker the harness writes last), the harness, in every node: deletes Docker's default routes (a node with a `Gateway` routes IPv4 and IPv6 through it instead); cuts the node off from Docker's bridge, the Docker VM's end of every lab network and the only way out: its addresses are blackholed and an nftables `netdev` table per interface (`tplab_<interface>`) drops every frame to or from its MAC, which also covers its IPv6 link-local address (published ports of other projects listen in the VM); points `/etc/resolv.conf` at nothing, so Docker's resolver never forwards a lookup out (lab names resolve through `/etc/hosts`, which lists every node); and the networks don't masquerade. A lab node can reach other lab nodes and nothing else, which `TestSmoke/hermetic` checks. Tests must not delete the `tplab_*` tables (no `nft flush ruleset` in a node: flush your own tables).
- **Topologies are declared in Go** and rendered to a Compose file under `lab/.run/<project>/` (ignored by git). There is no shared `compose.yaml` to edit: a test that needs another node declares it.

## The standard topology

```
device-a, device-b ── [devices] ── router ── [servers] ── server-1, server-2, internet
```

`lab.Standard()`: networks `devices` and `servers` (dual-stack), the `router` on both with forwarding on, devices and servers routing through it, `internet` (the target for egress and "direct" traffic) on the servers side. Servers have forwarding on too (relays, exits). Everything between the two sides crosses the router: that is where packets are captured, and where the censor goes (TP-024).

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

A `Packet` has `Src`, `Dst`, `Proto`, `SrcPort`, `DstPort`, `Payload` (after the TCP/UDP header; the whole message for ICMP), the whole `IP` packet, and where it was seen: `Network` (the lab network of the interface, "" for one the lab didn't create, e.g. a TUN) and `Outgoing`. Capture returns once tcpdump is listening, so nothing sent after it is missed.

The router sees each forwarded packet **twice**: arriving (`Network: "devices", Outgoing: false`) and leaving (`"servers"`, `Outgoing: true`); filter on one side when counting. Capture works on any node, not only the router.

## Tests that run inside a node

Unit tests that need root, network namespaces, netlink, nftables or a TUN live next to their code, with the usual guard:

```go
if os.Getenv("THINKPOL_LAB") == "" {
	t.Skip("needs the lab")
}
```

`make lab-test` compiles **every** package's tests for Linux and runs each package, as root, in a fresh lab node of its own with `THINKPOL_LAB=1` (working directory: the package's directory under `/src`), so these tests run there and skip everywhere else. The node is alone on one dual-stack network with no route out: tests create the namespaces, veths and TUNs they need. Packages run four at a time (`labctl gotest -p`), each binary with `-test.timeout=10m` unless given its own. For one package: `make lab-gotest PKG=./internal/... RUN=regexp`. From a lab test, `node.RunGoTests(t, "./internal/agent/...", "-test.run", "X")` runs packages inside any node of a topology (that node, not a fresh one).

## Isolation and safety

- **Names.** Every lab is a Compose project named `tplab-<checkout>-<hash of its path>` for `make lab-up`, plus `-t-<test>-<hash>` for a test's lab and `-gotest-<hash>` for in-node tests (`go run ./lab/labctl project` prints the prefix). `THINKPOL_LAB_PROJECT` replaces the checkout part (`[a-z0-9][a-z0-9-]*`, at most 40 characters), never the `tplab-` prefix. No container names are fixed.
- **Ownership is the checkout's path, not the name.** Every lab container and network is labelled `org.thinkpol.lab=1` and `org.thinkpol.lab.root=<checkout path>`. `make lab-down` and the clean-ups find labs by those labels, and remove a project only if its name starts with `tplab-` and every container and network in it carries `org.thinkpol.lab=1` and exactly this checkout's path. Volumes are never removed (the lab has none). Starting a lab under a name this checkout already uses replaces the old lab; under a name another checkout's lab uses (two checkouts with the same `THINKPOL_LAB_PROJECT`), it fails instead, and neither checkout can remove the other's labs.
- **Compose sees only the lab.** Tear-down runs `docker compose` from an empty directory with no `COMPOSE_*` variables, so no compose file or setting of anyone else's is ever loaded.
- **Subnets.** Each lab network gets a /24 from `172.16.0.0/16` and a /64 from a random unique-local /48. That range is the /16 just below Docker's default address pools (which start at `172.17.0.0/16`), so labs don't use up the addresses other projects on the daemon get; if it clashes with something of yours, set `THINKPOL_LAB_SUBNET_POOL`. The choice is checked against every network on the daemon, serialized host-wide by a lock file, and retried if Docker still reports an overlap.
- **A cap on labs.** At most `THINKPOL_LAB_MAX_LABS` (default 12) slots are held at once by labs from tests and in-node runs. The cap is kept with lock files in the temporary directory, so it is shared by everything that uses the same `TMPDIR` (normally all of one user's runs); runs with different `TMPDIR`s don't see each other's slots. All the labs one top-level test starts share one slot, so a test starting a second lab never waits for itself. `make lab-up`'s lab doesn't count once `labctl` has exited.
- **Leftovers.** `make lab-test` first removes labs whose checkout no longer exists (`labctl down -stale`), then, at the end, this checkout's test labs (unless `THINKPOL_LAB_KEEP` is set).

Several checkouts can run `make lab-test` at once, and `make lab-down` only removes its own checkout's labs.

## Environment

| Variable | Effect |
|---|---|
| `THINKPOL_LAB_PROJECT` | replaces the checkout part of project names (e.g. two runs from one checkout) |
| `THINKPOL_LAB_KEEP` | a failed test's lab stays up; `make lab-test` skips its final clean-up |
| `THINKPOL_LAB_MAX_LABS` | lab slots at once per `TMPDIR` (default 12; one per top-level test) |
| `THINKPOL_LAB_SUBNET_POOL` | IPv4 range for lab networks (default `172.16.0.0/16`) |
| `THINKPOL_LAB_GOARCH` | architecture to build for (default: the Docker server's) |

## Gotchas

- Two `make lab-test` runs in the *same* checkout clean up each other's test labs at the end; give one a different `THINKPOL_LAB_PROJECT`.
- Lab networks are not Docker `internal` networks on purpose: Docker drops forwarded IPv4 between internal networks, which would break the router. The sealing above keeps the lab closed instead.
- `getent hosts <node>` prefers IPv6; use `getent ahostsv4` for the IPv4 address.
- The image's tags accumulate as the Dockerfile changes; remove old ones with `docker image rm thinkpol-lab:<tag>`.
