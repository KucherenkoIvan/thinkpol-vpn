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

- **One image**, `lab/Dockerfile`: Debian slim with iproute2, nftables, iputils, tcpdump, curl. It is tagged with a hash of the Dockerfile, so checkouts share it and a changed Dockerfile builds a new tag (the first build takes about a minute).
- **No Go inside.** `thinkpol` is cross-compiled on the host (`GOOS=linux CGO_ENABLED=0`, `GOARCH` of the Docker server, override with `THINKPOL_LAB_GOARCH`) into `lab/bin`, which every node mounts read-only at `/opt/thinkpol/bin` (on `PATH`). The checkout is mounted read-only at `/src` for test data.
- **Every node** is privileged, has `/dev/net/tun`, `THINKPOL_LAB=1` and `LAB_NODE=<name>` in its environment, and runs `sleep infinity` under an init unless the topology says otherwise.
- **Routes are the lab's, not Docker's.** After start the harness deletes Docker's default routes in every node and, for a node with a `Gateway`, routes IPv4 and IPv6 through it. Nothing has a route out of the lab, so tests are hermetic.
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

- **Nodes:** `l.Node(name)` gives `IPv4(network)`, `IPv6(network)`, `Exec(ctx, args...)` (a non-zero exit is an error, `Result` has stdout, stderr and the code), `MustExec(t, args...)` (returns stdout), `WriteFile(t, path, data)`, and `Start(t, args...)` for background processes (`Stop`, `Done`, `Output`; their output goes to the test log on failure).
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

`make lab-test` compiles **every** package's tests for Linux and runs them, as root, inside a lab node with `THINKPOL_LAB=1` (working directory: the package's directory under `/src`), so these tests run there and skip everywhere else. The node is alone on one dual-stack network with no default route: tests create the namespaces, veths and TUNs they need, and must clean them up (packages run one after another in the same node). For one package: `make lab-gotest PKG=./internal/... RUN=regexp`. From a lab test, `node.RunGoTests(t, "./internal/agent/...", "-test.run", "X")` does the same inside any node of a topology.

## Isolation

Every lab is a Compose project of its own: `<checkout>-<hash of its path>` for `make lab-up`, plus `-t-<test>-<hash>` for a test's lab and `-gotest` for in-node tests (`go run ./lab/labctl project` prints the prefix; `THINKPOL_LAB_PROJECT` overrides it). There are no fixed container names and no fixed subnets: Compose names containers after the project, and Docker allocates each network's IPv4 subnet and IPv6 /64, so labs never collide with each other or with any other Docker network. Several checkouts can run `make lab-test` at once, and `make lab-down` only removes its own checkout's projects.

## Gotchas

- Docker allocates subnets from its default pools (about 30 networks on a stock daemon, shared with everything else running). The standard topology uses two networks; with many labs running at once, `docker compose up` can fail with "all predefined address pools have been fully subnetted". Fewer parallel tests, or `make lab-down` in idle checkouts, fixes it.
- Two `make lab-test` runs in the *same* checkout clean up each other's test labs at the end; give one a different `THINKPOL_LAB_PROJECT`.
- Lab networks are not Docker `internal` networks on purpose: Docker drops forwarded IPv4 between internal networks, which would break the router. The lab is still closed, because no node has a route out.
- The image's tags accumulate as the Dockerfile changes; remove old ones with `docker image rm thinkpol-lab:<tag>`.
