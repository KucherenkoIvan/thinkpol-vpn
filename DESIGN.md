# thinkpol-vpn — Design

A self-hosted virtual network that survives a censor: your devices and VPS nodes form one private network (device ↔ device, device → exit node → internet), traffic between nodes is disguised by pluggable transports, and egress can be chained through several hops. The upkeep story Tailscale gets right — one command to join a node, keys and config handled for you — without its three problems: a WireGuard wire format the censor can block by protocol, clients depending on someone else's servers, and no chaining.

Built for taste, not for a deadline: every layer is a port with swappable adapters, so the interesting parts (transports, routing policy, path selection) stay easy to change. Product name **thinkpol-vpn**; the binary is **`thinkpol`** (split into `thinkpol-<role>` binaries only if a real need appears). Requirements, users and the release plan are in [PRD.md](PRD.md); this document is how.

## Threat model

The censor this is built against, and the feature that answers each technique:

| Censor technique | Answer |
|---|---|
| **DPI** — protocol fingerprints (WireGuard, OpenVPN), SNI and IP blocklists | WireGuard is never on the wire; links between nodes use **transports** that look like ordinary traffic |
| **Active probing** — connecting to a suspected server to see what answers | Transports authenticate before revealing anything; unauthenticated connections are forwarded to a real site (camouflage target) |
| **Profiling** — traffic shape, packet sizes and timing, TLS-in-TLS patterns, TLS fingerprints (JA3/JA4) | Browser-grade TLS fingerprints (uTLS); padding and batching in the transport (later) |
| **Whitelists** — only approved destinations reachable | **Chains**: the first hop is a whitelisted (typically domestic) VPS, which relays to a foreign exit. Disguise alone can't pass a whitelist. Whitelisted addresses are scarce, so **one entry serves several spaces** |
| **Seizure or inspection of a node** — in-country entries sit in the censor's jurisdiction | **Nodes know only what they need**: their own part of the map, opaque ids, no logs on disk, telemetry only in memory and sealed (see Node safety) |

Not defended against: a censor that blocks everything foreign, a node owner abusing what an entry inherently sees (member IPs and traffic volume on its links), and traffic analysis by a global observer.

## Rules

1. **WireGuard is the inner layer only.** It provides end-to-end crypto, per-peer routing and rekeying; it never touches the network directly. Everything it emits goes through the path layer and a transport.
2. **The controller is never a runtime dependency.** Configuration is a **signed network map**, not a live API. Nodes keep the last valid map indefinitely; with the controller switched off, the network keeps working and only stops changing.
3. **Chains are core, not an add-on.** A route to the internet is an ordered list of hops, chosen per destination by routing rules.
4. **No home-made crypto.** WireGuard (via wireguard-go), standard TLS, and NaCl-style sealed boxes. The project's own code decides *where* bytes go and *what they look like*, never how they are encrypted.
5. **Nodes know only what they need.** Every node can read only its own part of the map, and keeps nothing on disk it could do without.
6. **Spaces never touch.** On a shared node, each space gets its own network stack; nothing (packets, routes, DNS, telemetry) crosses between them.

## Architecture

Two planes. The **data plane** moves packets on every node; the **control plane** decides what the network looks like and publishes it as the signed map.

### Data plane (every node, one binary)

```
 TUN ──► router ──► WireGuard ──► path layer ──► transport ──► wire
        (rules)    (per egress)   (conn.Bind)    (per link)
```

| Layer | Responsibility | First adapter |
|---|---|---|
| **TUN** | Virtual interface on macOS (utun), Linux, Windows (Wintun) | `wireguard-go/tun` |
| **Router** | Classifies each packet by destination: overlay peer, a chain, or `direct`. Holds the rule table (longest-prefix match on IPs) | in-process |
| **WireGuard** | End-to-end sessions with peers (devices, exits). Fed by the router through virtual `tun.Device`s — **one WireGuard device per egress**, because WireGuard routes by `AllowedIPs` and two exits would both claim `0.0.0.0/0` | `wireguard-go/device` |
| **Path layer** | A `conn.Bind`: WireGuard sees one stable peer; underneath, each peer has **candidate paths** (via relay N, via relays A→B, later direct UDP) and the layer picks and switches between them | relay paths only |
| **Transport** | One link between two adjacent nodes; authenticates, frames packets, disguises the stream | plain UDP (the baseline the lab must catch) |

**Every server node relays; ingress and egress are opt-in.** Two node settings, both off by default: **allow ingress** (devices may connect, so the node can be a chain's first hop) and **allow egress** (internet traffic may leave from it, so it can be a chain's last hop). A node with both off accepts only other nodes and only relays. There are no fixed roles: what a node does in a chain comes from its position there, so the same VPS can start one chain, sit in the middle of another and end a third. Device-to-device relaying needs a relay devices can reach, so it uses nodes that allow ingress.

**Relays, chains and device-to-device are one mechanism.** A path is a list of relays ending at a peer. Device-to-device through a relay is a one-relay path; a chain `ru-entry → nl-exit` is a path to the exit peer via `ru-entry`. A relay forwards opaque WireGuard packets addressed by destination node id; it never decrypts them.

**Hop groups make failover a path-layer decision.** A chain hop can be a group (`ru-entries`) with a selection policy: `failover` (priority order), `lowest-latency`, or `spread` (each device sticks to one member, devices are distributed). The group expands into one candidate path per member; the path layer scores them (handshake success, loss, latency) and switches with hysteresis. WireGuard's session is with the exit, not the entry, so **switching entries keeps the exit and open connections survive**. No per-packet balancing across entries: packets would arrive out of order, which TCP handles badly. `spread` is the useful kind of balancing, and it also keeps any single entry IP's volume low against volume-based throttling.

**Transports** (roughly in order of how hard they are to catch):

| Transport | Shape | Notes |
|---|---|---|
| `udp` | sealed datagrams | baseline; WireGuard-sized packets and an hourly connection id, trivially profiled |
| `tls` | TLS 1.3 with a browser fingerprint (uTLS), probe fallback to a real site | the workhorse for client → entry. The client's auth token rides in the ClientHello, so a server can tell its clients from probes before answering anything: probes are proxied whole to the real site and see its certificate. The node's own certificate comes from a pluggable certificate source (self-signed and pinned by the client first; ACME with a real domain is optional, since probes never see it) |
| `ws` | WebSocket over TLS | can sit behind a CDN, which hides the node's IP |
| `reality`-style | borrows a real site's TLS handshake, no certificate of our own | later |
| `obfs-udp` | obfuscated datagrams | for direct device-to-device paths, where TCP hole punching is impractical |

Stream transports carry TCP inside TCP and degrade under loss; datagram transports are the first thing throttled under whitelists. Hence **transports are chosen per link**, not per network.

**The map says, the engine converts, the transport decides.** Each transport's settings (listener, dial side, inbound side) are its own protobuf messages in `proto/thinkpol/transport/v1/`: the controller encodes them, the transport's adapter decodes them, and the map and everything between carry them as opaque bytes. The conversion from the map to the transport port's types lives in the data-plane engine (`internal/dataplane`), not in `netmap` or the adapters; it checks each entry with the transport before using it. Endpoints in the map are IP literals: the controller resolves names, nodes never resolve them at dial time. Transports may rely on clocks: nodes' clocks must agree within five minutes (`udp` drops datagrams sealed further from its own clock).

**Transports own traffic shape.** WireGuard's fixed packet sizes and its rhythm (rekey every 2 minutes, keepalives) would show through any wrapper, and only the transport knows what traffic it's imitating. So padding, batching and timing are part of the transport contract, each with its own settings; the layers above never pad. The lab measures how much is enough per transport.

**Egress** (nodes that allow egress, Linux): IP forwarding + nftables masquerade for the overlay range. A userspace TCP/IP stack is a later alternative.

### Server agent: one worker per space

Server nodes run a **supervisor** and **one worker process per space**, from M0 on, even while a node serves only one space:

- **Each worker lives in its own Linux network namespace** with its own TUN, WireGuard devices, routing table, nftables rules, DNS resolver and per-space node keys. Spaces can't see each other's packets or routes because they don't share a network stack, not because code is careful. A crash in one space's worker leaves the others running.
- **The supervisor owns the public address**, the scarce resource. It accepts every incoming connection, runs the transport's authentication, maps the credential to a space, and hands the connection to that space's worker. Unauthenticated connections go to the camouflage target, so a probe sees one ordinary site whatever the number of spaces. On a node with ingress off, the listener accepts only other nodes' credentials, and the node's address is never written into a device's map section, so no device can leak it. The supervisor merges the spaces' credential tables, stamping each entry's space from the map it came from, never from what the map says.
  - **Datagram transports** carry a keyed connection id that tells the supervisor which credential to check; it authenticates each datagram before forwarding it, untouched, to the worker over the worker socket. The worker decrypts again and filters replays; a space's fair-share bucket is charged once the worker accepts a datagram.
  - **Stream transports** (`tls`) authenticate in the ClientHello: the token (an HMAC of the credential and a coarse timestamp, in the legacy session id via uTLS) is checked by the supervisor, which keeps a replay cache, by peeking at the ClientHello without terminating TLS. Authenticated: the connection's file descriptor and the bytes already read go to the space's worker (passed over a Unix socket), which terminates TLS with its own certificate, self-signed and pinned by the client. Anything else is proxied as a whole to the camouflage target, so a probe completes a handshake with the real site and sees its certificate.
- **Egress** leaves each namespace through its own veth pair and is masqueraded once in the node's root namespace, so all spaces exit from the node's public IP.
- **Fair share:** the supervisor enforces each guest space's bandwidth cap (token buckets per space, or tc classes per veth) and splits spare capacity under load.
- **Node-level control** (agent updates, which spaces the node serves, caps) belongs to the **node owner**, the admin of the space that owns the node. A guest space configures only its own worker, through its own map.

### Routing rules and DNS

An ordered rule list; first match wins:

```
domain-suffix:example.ru  → direct
geoip:ru                  → direct
geosite:youtube           → chain:nl
default                   → chain:ru-nl
```

Actions: `direct`, `chain:<name>`, `block`. The space's default list lives in the signed map; each device can override it locally (the "what goes through the tunnel" switch).

Two ways to enforce the same rules:

| Mode | How | Matches |
|---|---|---|
| **Route table** (first) | Install `direct` IP ranges as OS routes to the physical gateway, everything else into TUN. Merge adjacent CIDRs; country lists are thousands of prefixes, and Windows is slow with big tables | IP only (`geoip`, `cidr`); domain rules are skipped with a warning |
| **Userspace** (later) | Everything enters TUN; a userspace TCP/IP stack opens each connection itself, `direct` or tunneled | IP, domain (DNS interception, SNI), per app |

GeoIP alone misroutes CDNs (foreign services on domestic IPs and vice versa), so the rule format supports domains from day one even though enforcement comes later.

**DNS is routing.** A resolver on the node's overlay address answers overlay names (`<device>.<space>.internal`; `.internal` is reserved for private use, so a space name can never shadow a real domain), sends `direct` domains to a domestic upstream, and everything else through the tunnel to a resolver at the exit. No DNS leaks, and GeoIP isn't fed CDN answers from the wrong country.

**Lists**: v2fly geoip/geosite or DB-IP Lite. The map references them by content hash; nodes fetch and cache them from peers.

### IPv6

The risk is leaking: if the local network has IPv6 and the tunnel doesn't carry it, apps connect around the tunnel, past the rules and in view of the censor.

- **Overlay:** dual-stack. IPv4 from `100.64.0.0/10`, plus a **random ULA /48 per space** (RFC 4193). Spaces are isolated in their own namespaces, so overlapping IPv4 ranges on a shared node are harmless.
- **Egress:** exits with IPv6 do NAT66; without it, IPv6 is blocked while connected. Never leaked either way.
- **Everything is dual-stack:** route-table rules (GeoIP lists carry IPv6 ranges), DNS (`AAAA`), and the kill switch.
- **Entries reachable over IPv6** are extra candidate paths. Censors sometimes treat IPv6 differently, which deserves a lab module.

### Direct paths (hole punching)

A later candidate path, not a separate feature. Nodes learn their public endpoint from our own server nodes (never public STUN), try direct UDP, and keep the relay as the fallback. Under a whitelist, traffic between two home or mobile IPs may simply not get through. Direct paths reveal each device's real IP to the other and show the censor encrypted UDP between home IPs, so they are a per-space setting.

### Desktop client

Two processes. The **service** is the node agent: it runs privileged (TUN, routes, firewall), installed as a launchd daemon, systemd unit or Windows service. The **tray app** is unprivileged and talks to the service over a local socket (named pipe on Windows) with a small gRPC API: connect/disconnect, status, space switcher, rule presets, kill switch, connect-on-boot. The CLI is a third client of the same API.

A device can be enrolled in several spaces but runs **one at a time**: switching spaces tears down one data plane and brings up the other.

When the entry in use belongs to another space, the tray labels it **`owned by <space>`**: that space's node owner can see the member's IP and traffic volume (see Trust in the PRD).

**Kill switch:** while on and the tunnel is down, the firewall (pf, nftables, Windows Filtering Platform) allows only traffic to entry nodes, plus LAN when allow-LAN is set. A pause option covers captive portals.

### Node safety

What a censor finds on a seized or inspected server node:

| On the node | What it holds |
|---|---|
| Binary and systemd unit | — |
| Keys | One key set per space served; private keys generated on the node, never copied off |
| Map | Only the node's own decrypted part per space (see the signed map): ids, endpoints and credentials of the links it serves. **No member names, no rules it doesn't enforce, no other nodes' credentials.** Devices appear as opaque ids |
| Logs | None on disk. Agent logs go to an in-memory ring, readable over the overlay for debugging; provisioning sets journald to volatile storage |
| Telemetry | Only in memory, per space, bounded (on the order of 15 minutes and tens of kilobytes); **each record sealed to the space's telemetry key as it's written**, so neither a memory dump nor swap yields readable data; oldest dropped first; gone on reboot |

Telemetry records are aggregates per link and per device id (rates, byte counts, path and transport in use, handshake failures), **never public IP addresses or destinations**. History lives only on the controller.

Later: **ephemeral nodes** keep nothing on disk but the binary. After a reboot they are blank, and the node owner's controller re-provisions them over SSH.

### Control plane (the controller, on go-kernel)

A DDD service: CLI plus `thinkpol admin serve` for the web panel, reachable **only through the overlay**.

**Each admin runs their own controller**, managing that admin's spaces. The space's signing key lives there and nowhere else, so no one can sign another admin's map. Default placement: a server node the admin owns **outside the censor's jurisdiction**, so it's always on to receive telemetry. Running it on a laptop works too; dashboards then only fill while the laptop is up.

Everything is space-scoped: every aggregate carries its space id.

| Feature | Aggregates / responsibility |
|---|---|
| `spaces` | **Space**: name, signing public key, recovery public key, telemetry public key, IPv4 range, IPv6 ULA prefix |
| `members` | **Member**: role (`admin`, `member`), grants (which chains they may use, whether their devices are reachable space-wide) |
| `nodes` | **Node**: opaque id, display name (controller-only), owner member, kind (`server`, `device`), `allowIngress` and `allowEgress` (servers only, both default off), overlay addresses, WireGuard public key, offered transports and their credentials, camouflage target; **own** or **shared** (another space's node, used through a grant) |
| `hosting` | **HostingGrant**: shared node, guest space's public key, bandwidth cap, ingress and egress granted (at most what the node allows), state (`offered`, `accepted`, `revoked`). Offered and accepted as signed tokens passed out of band between the two admins, like invites |
| `topology` | **HopGroup**: members + selection policy. **Chain**: ordered hops (nodes or hop groups); invariants: hops distinct, first hop allows ingress, last hop allows egress (for a shared node: as granted to this space), and for a hop group every member does |
| `policy` | **RuleSet**: the space's default routing rules |
| `invites` | **Invite**: single-use, expiring join token carrying the space public key and the first node to contact; rendered as link and QR code |
| `provisioning` | Turning a fresh Linux box into a node over SSH, hardening included (volatile journald, no on-disk logs) |
| `publishing` | A projector: on any change, rebuild the space's map, bump its version, seal each node's part, sign, push out |
| `telemetry` | Ingests sealed node reports; 24 h rolling retention; node owners see per-space volume on their nodes, guests see only their own slice |

Events (`NodeJoined`, `NodeRemoved`, `MemberRemoved`, `GrantAccepted`, `GrantRevoked`, `ChainChanged`, `PolicyChanged`, `MapPublished`, `PathDegraded`, `TransportBlocked`) drive publishing and the dashboards.

**Admin panel.** Server-rendered with go-kernel's `webui` (htmx) for lists, forms and dashboards. The **canvas** (nodes, links, transports, chains as paths, live health and traffic on top, editing by dragging) is a JavaScript island on its page, a graph-editor library fed by a JSON endpoint and a live-update stream. Shared nodes appear on a guest's canvas as read-only, labelled `owned by <space>`. Whether islands like this belong in `webui` itself is a kernel question this project answers.

**The signed map.** One per space: a signed envelope with a header (space id, version, hashes of list files) and **one sealed section per node**, encrypted to that node's key. Each section holds only what its node needs:
- an entry gets the device ids it accepts, their transport credentials and where it may relay to
- an exit gets the WireGuard keys and overlay addresses of devices allowed to use it
- a device gets rules, chains, reachable peers and entry endpoints

Versions only go up, and the envelope is signed by the space's **signing key**. Nodes accept a valid envelope with a higher version from anyone, including other nodes, so it spreads by gossip, but each can open only its own section. Rollback is impossible, and there is no expiry, so offline networks keep working. Revocation is a new version without the node.

**The section count is padded** to a fixed size (8, 16, 32, …) with dummy sections, so the envelope doesn't reveal how many nodes a space has.

**Recovery key.** Created with the space and kept offline by the admin (printed phrase or QR code); never on the controller. The header carries its public key, and it can sign exactly one kind of record: "the signing key is now X". Nodes accept that record over the current signing key, so a lost or stolen controller is recovered by rotating to a new key instead of re-creating the space. Controller database backups are encrypted to the same key, so one thing kept offline restores everything.

**Shared nodes and maps.** The node owner's map tells the node which guest spaces it serves: each guest's public key and cap. The node then accepts the guest space's envelopes as well, but only for that guest's worker. To the guest's controller, the shared node is an endpoint plus the grant, with nothing to provision.

**Joining.**
- Server: `thinkpol node add root@1.2.3.4` installs the binary and a systemd unit, hardens logging, enables forwarding, configures nftables, has the node **generate its own keys**, adds it to the map with ingress and egress off, and publishes; `thinkpol node set <node> --ingress --egress` opens it up. Every step is idempotent, so re-running is how you repair a node.
- Device: `thinkpol join <invite>`.
- Sharing: the node owner runs `thinkpol grant offer <node> --ingress --cap 50mbit`, and the guest admin runs `thinkpol grant accept <token>`.
- Updates: signed release binaries, distributed through the network like list files.

**Kernel usage.** `config`, `app`, `observability`, `sqlite` and `webui` for the controller; `grpckit` for the push channel to nodes, which needs **streaming RPCs** (missing in grpckit today: add server and client stream interceptors there first). The data plane uses plain ports and adapters with no DDD aggregates: packets aren't domain events.

**Protobuf contracts live in this repo** under `proto/`, buf-managed (the map format, the local service API, the controller's node API), never in go-kernel's `contracts/`. This is a deliberate thinkpol-only exception to the kernel convention of hosting consumers' contracts: these schemas are wire formats between thinkpol's own binaries, not contracts between separate services.

## Repository layout

Follows go-kernel's service structure for the control plane; the data plane is its own tree of ports and adapters.

```
cmd/thinkpol/             # one binary: node agent / client service (`up`), CLI, `admin serve`, dev tools; one file per command
cmd/thinkpol-tray/        # unprivileged tray app, a client of the local service API
internal/
  agent/                  # the node agent on servers and devices: applies maps, runs the data plane, local API, service install, self-update
    supervisor/           # servers: owns the public address and the shared listener, starts one worker per space
    worker/               # servers: one space's data plane inside its own network namespace
  dataplane/              # the engine that wires the subpackages below, nothing else
    tun/ router/ wg/ path/
    transport/            # the transport port; adapters in transport/<name>/
    netcfg/               # interface addresses, MTU, routes (route-table rule enforcement)
    firewall/             # kill switch (pf, nftables, WFP)
    egress/ dns/
    blobs/                # fetch-by-hash distribution of list files and releases between peers
    telemetry/
  netmap/                 # the signed map: envelope, sealed sections, signing, verification, gossip
  lists/                  # GeoIP/geosite lists: importers, CIDR aggregation, the content-addressed blob format
  features/               # control plane bounded contexts (spaces, members, nodes, hosting, topology, policy, invites, provisioning, publishing, telemetry); no code in the root
    <feature>/adapters/http/   # that feature's admin panel pages
  shared/                 # shared/domain, shared/ports, shared/infra as in go-kernel; no code in the root
    infra/webui/          # the admin panel's page shell: layout, navigation, assets, the canvas island
proto/                    # buf module: the map format, the local service API, the controller's node API
  gen/                    # generated Go code, never hand-edited
lab/                      # censor lab (below)
```

- **OS specifics** are per-OS files (`_linux.go`, `_darwin.go`, `_windows.go`) inside the package they belong to; there is no separate platform tree.
- **Lists** are built offline (`thinkpol dev lists build`, later the controller), distributed by `dataplane/blobs`, and read by the router. `lists` sits outside `dataplane` because both planes use it.
- **Dependency direction**: `dataplane`, `netmap`, `lists` and `agent` never import `features` or `shared`; `dataplane`, `netmap` and `lists` don't import go-kernel; `features` never import `dataplane` or `agent`, nor each other (cross-feature calls go through `shared/ports`); `shared` never imports `features`. The planes meet only through the signed map.
- **Mobile**: everything under `dataplane`, `netmap` and `lists` is pure Go; all of it except `tun`, `egress` and `firewall` builds for Android.

## Censor lab

The test suite, and the definition of "done" for a transport. Docker Compose with a client, a **censor** container between client and entry, an entry, an exit, an "internet" target and a real site for camouflage. Censor modules, each switchable:

- IP and SNI blocklists
- WireGuard and OpenVPN fingerprints
- fully-encrypted-traffic heuristics (as in *How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic*, USENIX Security 2023)
- active prober
- JA3/JA4 fingerprint filtering
- whitelist mode
- volume-based throttling

Besides censor modules, the lab runs two non-censor checks:
- **Isolation:** two spaces share an entry, and every attempt to reach across fails.
- **Seizure:** a snapshot of a node's disk and memory is searched for member IPs, names and destinations.

`make lab` runs every transport against every module and regenerates a pass/fail matrix committed as `lab/RESULTS.md`.

## Milestones

Scope per milestone is in [PRD.md](PRD.md#release-plan); these are the technical "done" checks.

| | Milestone | Done when |
|---|---|---|
| M0 | Two Linux nodes in the lab, hand-made map in the sealed-section format, `udp` transport, relay paths; server agent as supervisor + one worker in its own namespace | `ping` device ↔ device, directly and via a relay, over IPv4 and IPv6 |
| M1 | Exit node with NAT, route-table rules with GeoIP, DNS, IPv6 handling, macOS and Linux CLI clients | daily-usable on its own terms; leak tests pass |
| M2 | `tls` transport with probe fallback; lab v1 (blocklists, WireGuard fingerprint, entropy, prober) | `udp` fails the lab, `tls` passes |
| M3 | Chains and hop groups with failover; lab whitelist mode | `ru-entries → nl-exit` passes a whitelist; killing the active entry keeps an open connection alive |
| M4 | Controller on go-kernel: spaces, members, invites, SSH provisioning with hardening, map gossip, hosting grants and shared nodes, telemetry, admin panel with canvas | a fresh box joins with one command and shows up on the canvas; a second space shares the entry and the isolation and seizure checks pass |
| M5 | Desktop client: service + tray app on macOS, Linux, Windows; kill switch; connect-on-boot; invite links; space switcher | a non-technical member joins from an invite without a terminal |

After the MVP: Android, userspace enforcement (domain rules), direct paths, traffic shaping, `ws` behind a CDN, ephemeral nodes.

## Out of scope (for now)

VPS provider APIs (every node is a fresh Linux box you rent yourself), automatic IP rotation (needs provider APIs), onion-layered encryption across hops, iOS, our own crypto. Android is the first step after the MVP, so data-plane packages must stay buildable for mobile (no cgo, no desktop-only dependencies outside `tun`, `egress` and the firewall adapters).

## Open questions

None right now; new ones go here.
