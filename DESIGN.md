# thinkpol-vpn — Design

A self-hosted virtual network that survives a censor: your devices and VPS nodes form one private network (device ↔ device, device → exit node → internet), traffic between nodes is disguised by pluggable transports, and egress can be chained through several hops. The upkeep story Tailscale gets right — one command to join a node, keys and config handled for you — without its three problems: a WireGuard wire format the censor can block by protocol, clients depending on someone else's servers, and no chaining.

Built for taste, not for a deadline: every layer is a port with swappable adapters, so the interesting parts (transports, routing policy, path selection) stay easy to change. Product name **thinkpol-vpn**; the binary is **`thinkpol`** (split into `thinkpol-<role>` binaries only if a real need appears). Requirements, users and the release plan are in [PRD.md](PRD.md); this document is how.

This document is the model: what must stay true, and why. The mechanism (numbers, paths, OS details) is in the package docs, listed in [Where the mechanism lives](#where-the-mechanism-lives). What the design accepts falling short of is in [RESIDUAL-RISKS.md](RESIDUAL-RISKS.md), each case with its ticket (none for what the threat model leaves undefended).

## Security

The threat model, the rules, the IPv6 leak guard, the kill switch and node safety are in [security](docs/design/security.md). Read it first: every other design file assumes it.

## Architecture

Two planes. The **data plane** moves packets on every node; the **control plane** decides what the network looks like and publishes it as the signed map.

Each area's design is a file of its own under `docs/design/`; this file is the entry point and the index:

| File | Topic |
|---|---|
| [Security](docs/design/security.md) | the threat model, the rules, the IPv6 leak guard, the kill switch, node safety |
| [Overlay](docs/design/overlay.md) | the data plane, IPv6 addressing, destination routing, direct paths, the node agent |
| [Transports](docs/design/transports.md) | the transport port and traffic shape |
| [Server agent](docs/design/server-agent.md) | the supervisor, one worker per space, egress |
| [Routing](docs/design/routing.md) | routing rules, the route table, DNS, lists |
| [Desktop client](docs/design/desktop-client.md) | the client and the local API |
| [Control plane](docs/design/control-plane.md) | the controller, the signed map, joining, kernel usage |
| [Censor lab](docs/design/lab.md) | the lab and its censor modules; device testing |
| [Milestones](docs/design/milestones.md) | the done-when checks, out of scope |

## Where the mechanism lives

Each package's `doc.go` holds its mechanism; this table is the way in.

| Package | Role |
|---|---|
| `cmd/thinkpol` | the one binary (`up`, CLI, `admin serve`, dev tools); composition roots |
| `cmd/thinkpol-tray` | the tray app, a local API client |
| [`agent`](internal/agent/doc.go) | the node agent: maps, modes, host lock, connection, events, what a node keeps |
| [`agent/service`](internal/agent/service/doc.go) | installing the agent as the host's service: the systemd unit, the launchd daemon, connect-on-boot |
| [`agent/supervisor`](internal/agent/supervisor/doc.go) | servers: shared listeners, isolation, egress; the planned gatekeeper |
| [`agent/worker`](internal/agent/worker/doc.go), [`agent/ipc`](internal/agent/ipc/doc.go) | a space's sandboxed data plane and its protocol |
| [`agent/localapi`](internal/agent/localapi/doc.go) | the local API: socket, gates, limits |
| [`agent/logring`](internal/agent/logring/doc.go) | the bounded in-memory log ring |
| [`dataplane`](internal/dataplane/doc.go) | the engine: its ports, the overlay's MTU |
| [`dataplane/tun`](internal/dataplane/tun/doc.go) | the overlay interface |
| [`dataplane/router`](internal/dataplane/router/doc.go) | classifying packets by destination; local reflection on macOS |
| [`dataplane/wg`](internal/dataplane/wg/doc.go) | the WireGuard devices, one per egress |
| [`dataplane/path`](internal/dataplane/path/doc.go) | destination routing, liveness, failover |
| [`dataplane/transport`](internal/dataplane/transport/doc.go), [`shaping`](internal/shaping/doc.go) | the transport port, shaping, planned stream transports |
| [`dataplane/transport/udp`](internal/dataplane/transport/udp/doc.go) | `udp`: wire format, replay rules, bounds |
| [`dataplane/rules`](internal/dataplane/rules/doc.go) | matchers, presets, compilation into prefixes |
| [`dataplane/routetable`](internal/dataplane/routetable/doc.go), [`dataplane/netcfg`](internal/dataplane/netcfg/doc.go) | route-table mode on Linux and macOS; routes and rules |
| [`dataplane/ifbind`](internal/dataplane/ifbind/doc.go), [`dataplane/trusteddir`](internal/dataplane/trusteddir/doc.go), [`dataplane/nsthread`](internal/dataplane/nsthread/doc.go) | socket binding; trusted directories; namespace threads |
| [`dataplane/firewall`](internal/dataplane/firewall/doc.go) | the IPv6 leak guard (nftables, pf); later the kill switch |
| [`dataplane/egress`](internal/dataplane/egress/doc.go) | a server's uplink |
| [`dataplane/dns`](internal/dataplane/dns/doc.go) | the resolver; pointing the OS at it |
| [`dataplane/blobs`](internal/dataplane/blobs/doc.go), [`lists`](internal/lists/doc.go) | lists and their distribution |
| [`netmap`](internal/netmap/doc.go), [`devmap`](internal/devmap/doc.go) | the signed map; hand-made maps |
| [`features`](internal/features/doc.go), [`shared`](internal/shared/doc.go) | the controller; the planned canvas |
| `proto` | the buf module; `gen/` is generated |
| [`lab/censor`](lab/censor/doc.go), [lab/README.md](lab/README.md) | the censor framework and the lab |
| [`lab/devicetest`](lab/devicetest/doc.go), [`lab/devicetest/safety`](lab/devicetest/safety/doc.go) | the device-test harness: what a run guarantees, how a plan is written, and its frozen safety core |

### Repository layout

- **OS specifics** are per-OS files (`_linux.go`, `_darwin.go`, `_windows.go`) inside the package they belong to; there is no separate platform tree.
- **Lists** sit outside `dataplane` because both planes use them: built offline (`dev lists build`, later the controller), distributed by `dataplane/blobs`, read by the rules.
- **Dependency direction**: `dataplane`, `netmap`, `lists` and `agent` never import `features` or `shared`; `dataplane`, `netmap` and `lists` never import `agent`; `dataplane`, `netmap` and `lists` don't import go-kernel; `features` never import `dataplane` or `agent`, nor each other (cross-feature calls go through `shared/ports`); `shared` never imports `features`. The planes meet only through the signed map.
- **Mobile**: everything under `dataplane`, `netmap` and `lists` is pure Go; all of it except `tun`, `egress` and `firewall` builds for Android.

## Open questions

- **Admin panel: organisation, authentication and authorization.** The owner hasn't decided how the panel is organised, so none of this is designed: who may sign in, what each role may see and change, sessions, CSRF on the forms, what the canvas endpoint exposes. To be designed before TP-042 starts; overlay reachability is not access control.
