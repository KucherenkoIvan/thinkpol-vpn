# thinkpol-vpn — Design

A self-hosted virtual network that survives a censor: your devices and VPS nodes form one private network (device ↔ device, device → exit node → internet), traffic between nodes is disguised by pluggable transports, and egress can be chained through several hops. The upkeep story Tailscale gets right — one command to join a node, keys and config handled for you — without its three problems: a WireGuard wire format the censor can block by protocol, clients depending on someone else's servers, and no chaining.

Built for taste, not for a deadline: every layer is a port with swappable adapters, so the interesting parts (transports, routing policy, path selection) stay easy to change. Product name **thinkpol-vpn**; the binary is **`thinkpol`** (split into `thinkpol-<role>` binaries only if a real need appears). Requirements, users and the release plan are in [PRD.md](PRD.md); this document is how.

This document is the model: what must stay true, and why. The mechanism (numbers, paths, OS details) is in the package docs, listed in [Where the mechanism lives](#where-the-mechanism-lives). What the design accepts falling short of is in [RESIDUAL-RISKS.md](RESIDUAL-RISKS.md), each case with its ticket (none for what the threat model leaves undefended); `RRn` below names its rows.

## Threat model

The censor this is built against, and the feature that answers each technique:

| Censor technique | Answer |
|---|---|
| **DPI** — protocol fingerprints (WireGuard, OpenVPN), SNI and IP blocklists | WireGuard is never on the wire; links between nodes use **transports** that look like ordinary traffic |
| **Active probing** — connecting to a suspected server to see what answers | Transports authenticate before revealing anything; unauthenticated connections are forwarded to a real site (camouflage target; not yet: RR30) |
| **Profiling** — traffic shape, packet sizes and timing, TLS-in-TLS patterns, TLS fingerprints (JA3/JA4) | Browser-grade TLS fingerprints (uTLS); padding, batching and timing in the transport (the shaping contract; tuned by the lab) |
| **Whitelists** — only approved destinations reachable | **Chains**: the first hop is a whitelisted (typically domestic) VPS, which relays to a foreign exit. Disguise alone can't pass a whitelist. Whitelisted addresses are scarce, so **one entry serves several spaces**. An allowlisted entry exists only where someone already controls an approved address (PRD Decisions, "Whitelist scope"): thinkpol uses one when it exists and doesn't promise a way past whitelist mode without one. Under whitelist mode only TCP passes, even to listed addresses |
| **Seizure or inspection of a node** — in-country entries sit in the censor's jurisdiction | **Nodes know only what they need**: their own part of the map, opaque ids, no logs on disk, telemetry only in memory and sealed (see Node safety) |
| **Seizure or compromise of a member device** — it sits in the censor's jurisdiction and keeps its key on disk | Not prevented; bounded. The device holds valid credentials, so an entry can't tell the censor from the member, and nothing in telemetry detects it. Its section shows its entries' endpoints, its chains, rules and peer ids, and it reaches whatever the member could. **Per-device grants (A3)** bound the damage: only the chains and devices it was granted. **Revocation** is a new map without the device and spreads by gossip as soon as one honest entry is reachable |
| **Apps on a member's device** — government-affiliated apps that probe whether blocked services answer and look for VPN state: interfaces, routes, DNS, reachability | Partly hidden, honestly. Can't be hidden: a TUN (`utun`) interface and its routes are visible to every local app, so is the resolver's configuration, and a blocked service that answers shows that something carries it; Android's VpnService is detectable by design. What helps: "all but domestic" keeps domestic apps' traffic on the domestic path (not the interface or the routes). Per-app split tunnelling in userspace mode is the later mitigation |

Not defended against: a censor that blocks everything foreign, a node owner abusing what an entry inherently sees (member IPs and traffic volume on its links) or running a modified binary (what the PRD says a node owner never sees holds for an owner running the honest one), and traffic analysis by a global observer (RESIDUAL-RISKS.md, Not defended).

## Rules

1. **WireGuard is the inner layer only.** It provides end-to-end crypto, per-peer routing and rekeying; it never touches the network directly. Everything it emits goes through the path layer and a transport; on macOS a foreign host route to a peer's overlay address bypasses it (RR23).
2. **The controller is never a runtime dependency.** Configuration is a **signed network map**, not a live API. Nodes keep the last valid map indefinitely; with the controller switched off, the network keeps working and only stops changing.
3. **Chains are core, not an add-on.** A route to the internet is an ordered list of hops, chosen per destination by routing rules.
4. **No home-made crypto.** WireGuard (via wireguard-go), standard TLS, and NaCl-style sealed boxes. The project's own code decides *where* bytes go and *what they look like*, never how they are encrypted.
5. **Nodes know only what they need.** Every node can read only its own part of the map, and keeps nothing on disk it could do without.
6. **Spaces never touch.** On a shared node, each space gets its own network stack; nothing (packets, routes, DNS, telemetry) crosses between them.
7. **What a node can't resolve fails closed, with named exceptions.** A list not fetched, a matcher, action or shaping field it doesn't know, a preset the map can't build: none of them widens what goes direct or what a transport reveals; they block or refuse, and health says so. The exceptions are decisions, each a residual row: a section without rules, or with rules its node can't read, sends everything direct (RR28); an OS that can't host the IPv6 leak guard still connects (RR10, RR12); and until the node's own ceiling exists, the map alone decides a node's role (RR42).

## Architecture

Two planes. The **data plane** moves packets on every node; the **control plane** decides what the network looks like and publishes it as the signed map.

Each area's design is a file of its own under `docs/design/`; this file is the entry point and the index:

| File | Topic |
|---|---|
| [Security](docs/design/security.md) | the threat model, the rules, the IPv6 leak guard, node safety |
| [Overlay](docs/design/overlay.md) | the data plane, destination routing, direct paths |
| [Transports](docs/design/transports.md) | the transport port and traffic shape |
| [Server agent](docs/design/server-agent.md) | the supervisor, one worker per space, egress |
| [Routing](docs/design/routing.md) | routing rules, the route table, DNS, lists |
| [Desktop client](docs/design/desktop-client.md) | the client, the local API, the kill switch, the node agent |
| [Control plane](docs/design/control-plane.md) | the controller, the signed map, joining, kernel usage |
| [Censor lab](docs/design/lab.md) | the lab and its censor modules |
| [Milestones](docs/design/milestones.md) | the done-when checks, out of scope |

## Where the mechanism lives

Each package's `doc.go` holds its mechanism; this table is the way in.

| Package | Role |
|---|---|
| `cmd/thinkpol` | the one binary (`up`, CLI, `admin serve`, dev tools); composition roots |
| `cmd/thinkpol-tray` | the tray app, a local API client |
| [`agent`](internal/agent/doc.go) | the node agent: maps, modes, host lock, connection, events, what a node keeps |
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

### Repository layout

- **OS specifics** are per-OS files (`_linux.go`, `_darwin.go`, `_windows.go`) inside the package they belong to; there is no separate platform tree.
- **Lists** sit outside `dataplane` because both planes use them: built offline (`dev lists build`, later the controller), distributed by `dataplane/blobs`, read by the rules.
- **Dependency direction**: `dataplane`, `netmap`, `lists` and `agent` never import `features` or `shared`; `dataplane`, `netmap` and `lists` never import `agent`; `dataplane`, `netmap` and `lists` don't import go-kernel; `features` never import `dataplane` or `agent`, nor each other (cross-feature calls go through `shared/ports`); `shared` never imports `features`. The planes meet only through the signed map.
- **Mobile**: everything under `dataplane`, `netmap` and `lists` is pure Go; all of it except `tun`, `egress` and `firewall` builds for Android.

## Open questions

- **Admin panel: organisation, authentication and authorization.** The owner hasn't decided how the panel is organised, so none of this is designed: who may sign in, what each role may see and change, sessions, CSRF on the forms, what the canvas endpoint exposes. To be designed before TP-042 starts; overlay reachability is not access control.
