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

### Data plane (every node, one binary)

```
 TUN ──► router ──► WireGuard ──► path layer ──► transport ──► wire
        (rules)    (per egress)   (conn.Bind)    (per link)
```

| Layer | Responsibility |
|---|---|
| **TUN** | Virtual interface on macOS (utun), Linux, Windows (Wintun) |
| **Router** | Classifies each packet by destination: overlay peer, a chain, or `direct`. Holds the rule table (longest-prefix match on IPs) |
| **WireGuard** | End-to-end sessions with peers (devices, exits), fed by the router through virtual TUNs — **one WireGuard device per egress**, because WireGuard routes by `AllowedIPs` and two exits would both claim `0.0.0.0/0` |
| **Path layer** | A `conn.Bind`: WireGuard sees one stable peer; underneath, each peer has **candidate paths**, named by their first hop (a relay, or the peer itself; later direct UDP), and the layer picks and switches between them; relays route the rest of the way by destination |
| **Transport** | One link between two adjacent nodes; authenticates, frames packets, disguises the stream. First adapter: plain UDP, the baseline the lab must catch |

**Every server node relays; ingress and egress are opt-in.** Two node settings, both off by default: **allow ingress** (devices may connect, so the node can be a chain's first hop) and **allow egress** (internet traffic may leave from it, so it can be a chain's last hop). A node with both off accepts only other servers and only relays. There are no fixed roles: a node's position in a chain says what it does, so one VPS can start one chain, relay for another and end a third. Device-to-device relaying uses nodes that allow ingress, which devices can reach.

**Relays, chains and device-to-device are one mechanism: destination routing.** A relay forwards opaque WireGuard packets by destination node id; it never decrypts them. Each relay's map section holds a forwarding table (per destination, the adjacent next hops); a sender knows only its candidate first hops per peer, so **no node holds a whole path**. Device-to-device through a relay is a first hop whose route delivers to the device; a chain `ru-entry → nl-exit` is the exit peer reached with `ru-entry` as first hop. A hop limit, capped by every relay, ends any routing loop a map contains.

**Hop groups make failover a path-layer decision.** A chain hop can be a group (`ru-entries`) with a selection policy: `failover` (priority order), `lowest-latency`, or `spread` (each device sticks to one member, devices are distributed). Links don't report liveness, so a link counts as up only while its own probes are answered, and the path layer switches with hysteresis. Through M2 failover follows a node's own first-hop or next-hop links, in priority order; scoring, the other policies and the end-to-end probes that find a break further on come with hop groups (M3, RR48). WireGuard's session is with the exit, not the entry, so **switching entries keeps the exit and open connections survive**. No per-packet balancing across entries: packets would arrive out of order, which TCP handles badly. `spread` is the useful kind of balancing, and it also keeps any single entry IP's volume low against volume-based throttling.

#### Transports

Roughly in order of how hard they are to catch:

| Transport | Shape | Notes |
|---|---|---|
| `udp` | sealed datagrams | the baseline; trivially profiled (RR30) |
| `tls` | TLS 1.3 with a browser fingerprint (uTLS), probe fallback to a real site | after the MVP, node-to-node links (TP-028) |
| `ws` | WebSocket over TLS | can sit behind a CDN, which hides the node's IP |
| `reality` | REALITY's handshake: a browser ClientHello that seals the client's id; failed auth is spliced to a real site | the disguised transport for client → entry (M2, TP-087); no certificate of our own |
| `obfs-udp` | obfuscated datagrams | direct device-to-device paths, where TCP hole punching is impractical |

Stream transports carry TCP inside TCP and degrade under loss; datagram transports are the first thing throttled under whitelists. Hence **transports are chosen per link**. How stream transports authenticate and treat replays is in [`transport`](internal/dataplane/transport/doc.go); what a server's own hello still tells a censor is RR31. A "bridge" node type (a VLESS ingress routed into the overlay) was considered and set aside as too complex for now.

**The map says, the engine converts, the transport decides.** Each transport's settings are its own protobuf messages: the controller encodes them, the transport's adapter decodes them, and the map and everything between carry them as opaque bytes. The engine converts the map to the transport port and checks every entry with the transport before using it. Endpoints in the map are IP literals: the controller resolves names, nodes never resolve them at dial time. Nodes' clocks must agree within five minutes.

**Transports own traffic shape.** WireGuard's fixed packet sizes and its rhythm (rekey every 2 minutes, keepalives) would show through any wrapper, and only the transport knows what traffic it's imitating. So padding, batching, timing and cover traffic are part of the transport contract (C6), and the layers above never pad; they only mark the packets that keep a link warm, so a transport can fold their rhythm into its own.

- **Per end, from the map, never negotiated:** each end shapes what *it* sends; receivers undo shaping from the wire format alone.
- **Refuse, never weaken:** an adapter refuses a link whose shaping it can't honour, and a node refuses shaping fields it doesn't know, rather than shape less than the map asks. Shaping sits inside the transport's encryption and never touches its authentication or replay protection.
- **Rollout:** refusing is safe only if the controller never asks a node for what it can't do. So it puts a shaping (or a new shaping field or value) into a link only once both ends' nodes reported supporting it, in the version and capabilities agents report when they register and update; until then the link goes unshaped or keeps its old shaping.

The lab measures how much shaping is enough per transport and tunes the defaults (none, until it says otherwise).

**Egress** is a Linux server's worker forwarding and masquerading its space's internet traffic (NAT66 for IPv6); a node in device mode never forwards, whatever its section says.

### Server agent: one worker per space

Server nodes run a **supervisor** and **one worker process per space**, from M0 on, even while a node serves only one space.

- **Each worker lives in its own Linux network namespace** with its own TUN, WireGuard devices, routing table, firewall rules, resolver and per-space node keys. Spaces can't see each other's packets or routes because they don't share a network stack, not because code is careful. A crash in one space's worker leaves the others running.
- **Workers are sandboxed and tied to the supervisor.** A worker's privileges apply only inside its own namespaces, and it never outlives the supervisor; a crashed one restarts in a fresh namespace. Resource limits: RR38.
- **The root namespace keeps the spaces apart.** A worker owns its veth, so isolation can't rest on the spaces' routes: in the root namespace a space can send only from its own transit address and receive only replies to its own flows, so a forged packet or ICMP error can't touch another space's flows or the root's.
- **The supervisor owns the public address**, the scarce resource. It authenticates every incoming connection or datagram, maps the credential to a space by the map that listed it (never by what the map says), and hands the traffic to that space's worker. Unauthenticated traffic goes to the camouflage target, so a probe sees one ordinary site whatever the number of spaces (no camouflage exists yet: RR30). With ingress off, a node accepts only other servers, and its address is never written into a device's section; the node enforces that itself.
- **A worker answers its peers, never anyone else.** Its replies leave only to addresses its space's own authenticated, fresh, non-replayed datagrams recently came from, so it can't use the node's public address to reach anyone else, whatever egress its space has. Within one supervisor's lifetime a replay, which needs only a passive tap, is dropped before it reaches a worker or costs its space anything (RR34).
- **Pre-authentication parsing moves out of the root supervisor** into an unprivileged, sandboxed **gatekeeper** holding no space keys beyond what verification needs, so a memory-safety bug there doesn't cost a root process with every space's credentials (RR37).
- **A replay must not be an oracle.** In the planned stream transports a replayed handshake takes exactly the camouflage path, with the same upstream connection and timing: dropping or resetting it would tell a member's handshake from a stranger's. `udp` drops replays, but answers one after a supervisor or device-mode restart (RR34).
- **Bounded state.** Everything kept about unauthenticated or replayable traffic is bounded, so no peer can grow a node's state without limit; a bound that is hit refuses rather than forgets wherever forgetting would let a replay back in (`udp`'s memory of evicted senders forgets: RR36).
- **The camouflage target is chosen per node**, not defaulted fleet-wide: one default shared by every node is a fingerprint of the fleet, and the target should be plausible for the node's address and network (RR32).
- **Egress:** all spaces exit from the node's public IP. A space's traffic reaches the internet only for the families its map grants and the uplink carries, never the destinations no space should reach (metadata services, private networks), enforced in its namespace and again in the root. Forwarding the supervisor turns on carries only the spaces' traffic and is put back when no space needs it or the supervisor closes; a host that already forwards is left alone, its forwarding unconfined.
- **Fair share:** the supervisor enforces each guest space's bandwidth cap and splits spare capacity under load (not wired yet: RR38).
- **The node's own configuration is a ceiling over the map** (planned, TP-111; until then RR42; PRD Decisions). What a machine may do is allowed on the machine, by whoever runs it: `device`, or `server` with ingress, egress and relaying each opted into locally, the way a Tailscale device advertises itself as an exit node before an admin can use it. The space's signed map acts within the ceiling and can never widen it: peers, keys and revocations are always taken from a newer map, a role beyond the ceiling never is, and the node says so. Nodes need no agreement among themselves: to the space, a node that refuses a role is like one that is down, which hop groups route around. Each node enforces it even once the controller checks it: a controller can be compromised.
- **Node-level control** (updates, which spaces it serves, caps) is the **node owner's**, within the node's ceiling; a guest space configures only its own worker, through its own map.

### Routing rules and DNS

An ordered rule list; first match wins:

```
domain-suffix:example.ru  → direct
geoip:ru                  → direct
geosite:youtube           → chain:de
default                   → chain:ru-nl
```

Actions: `direct`, `chain:<name>`, `block`. Matchers by address (`local`, `cidr:`, `geoip:`), by name (`domain:`, `domain-suffix:`, `geosite:`, enforced by DNS and, later, userspace mode), and `default`. GeoIP alone misroutes CDNs (foreign services on domestic IPs and vice versa), so the rule format supports domains from day one even though enforcement comes later.

The space's default list lives in the signed map, in each device's section, with the chains it names and what the presets are built from (a domestic list and a chain). Each device can override it locally (the "what goes through the tunnel" switch): a base, the space's rules or a preset (**everything**, **all but domestic**), with the device's own rules ahead of it.

**Nothing unknown widens what goes direct.** The space's overlay networks are decided by peers, before any rule. A preset the map can't build fails closed, never back to the space's rules. A rule whose addresses aren't known (a list not fetched yet, a matcher the node doesn't know) matches nothing and, unless it was a `direct` rule itself, turns off the `direct` rules after it; an unknown action, or a chain that can't carry traffic, blocks; a destination no rule matches is blocked. The exception: a section without rules, or with rules its node can't read, routes nothing outside the overlay into the tunnel (RR28).

**Chains in use at the same time end at different exits.** WireGuard holds one session per exit and the path layer sends each exit's packets along one path at a time, so two chains to the same exit can't both carry traffic: they are alternatives, which a hop group expresses better. The map builder rejects a rule set that uses two chains ending at the same exit.

Two ways to enforce the same rules:

| Mode | How | Matches |
|---|---|---|
| **Route table** (first) | Install `direct` IP ranges as OS routes to the physical gateway, everything else into TUN | IP only (`geoip`, `cidr`); domain rules are skipped with a warning |
| **Userspace** (later) | Everything enters TUN; a userspace TCP/IP stack opens each connection itself, `direct` or tunneled | IP, domain (DNS interception, SNI), per app |

#### Route table

What route-table mode guarantees on every OS:

- **Only the rules decide what bypasses the tunnel**: the direct destinations and the links' own endpoints. No route another party adds (DHCP classless routes, TunnelVision; a public subnet declared on-link, LocalNet; another VPN's) takes tunnelled traffic around the tunnel. A local network is trusted only where it lies inside the local ranges *and* the rules send it direct; hosts on a public on-link LAN go through the tunnel. macOS, which has no policy routing, can only shadow foreign routes, after a debounce, and never a host route (RR22, RR23).
- **The links bypass the tunnel by their sockets**, and their endpoints are routed around it too, so a link never loops into its own tunnel, and nothing names the gateway where the OS lets us avoid it: roaming needs no change.
- **What the TUN can't take is refused**, not sent around the tunnel: IPv6 when the overlay doesn't carry it, and the overlay's own networks always. While the TUN is down IPv6 stays refused, but IPv4 follows the physical default route for a debounce first (RR19), and after a crash until the next start (RR18).
- **Direct shrinks before the router changes and grows after**, so a rule change never sends a tunnelled destination direct; a failed shrink falls back to nothing direct; if that fails too, the old set stays (RR14).
- **Everything installed is ours by mark and record**, so a restart after a crash takes it over, a stop removes it, and nothing of other software is touched.
- **Sockets the routing table can't hold** (bound to an interface, or routed by their source address) are the firewall's: the IPv6 leak guard confines them now; IPv4's wait for the kill switch (RR21).
- **The table is kept in place**: re-applied on every change of links, addresses or routes and periodically; health says when it isn't enforced.

#### DNS

**DNS is routing.** A resolver on the node's overlay address answers overlay names (`<device>.<space>.internal`; `.internal` is reserved for private use, so a space name can never shadow a real domain), sends `direct` names to a domestic upstream, and everything else through the tunnel to a resolver at the exit. So GeoIP isn't fed CDN answers from the wrong country, and names don't leak, but for the rows whose Breaks column names R4.

- **A name goes where its rule sends it**: the device's effective rule list read by name, with the same fail-closed rules as the route table. A name's rule picks only the upstream; the answer's addresses are routed by the address rules like any other. A tunnel-bound query leaves through the tunnel or not at all. A `direct` name aliased into a tunnel-bound one tells the domestic upstream its target (RR1).
- **Names stay inside the space.** Overlay names are in devices' sections only, so a server holds no member names, and a device names exactly the peers it has now. Nothing under `.internal` and no reverse name of the overlay is ever forwarded; forwarded queries carry none of the client's EDNS options.
- **Answers never cross routes**: they are cached per route and the cache is flushed on every map or rule change, so a direct upstream's answer is never served for a name that goes through the tunnel.
- **Upstreams.** An exit asks public resolvers, not the host's: on most clouds the host's sit on private or link-local addresses, which the worker's egress refuses, and widening it would open the provider's network, metadata services included, to every space. An upstream the egress refuses is reported, never silently dropped.
- **The OS resolves through the node while it is connected**, and gets its own configuration back when the device disconnects, stops or restarts after a crash. Where the OS can't be made to, it is never assumed: health and `thinkpol connect` say so while the tunnel stays up (RR2).
- **Nothing is logged about a query**: no names or answers in any log or on disk; the resolver keeps counters only.

#### Lists

GeoIP lists are blobs the map references by content hash: one list per blob in a canonical encoding, so the same addresses always give the same hash. They are built from files the operator downloads (no third-party data lives in the repo) and travel between peers inside WireGuard: nodes never fetch from outside the network. A node uses a blob only once it matches the map, and replaces a list in use only once its successor is verified. Servers serve only blobs a signed map of their space listed, so they are no oracle beyond that set; the hashes themselves are visible to every holder of the envelope (RR45).

### IPv6

The risk is leaking: if the local network has IPv6 and the tunnel doesn't carry it, apps connect around the tunnel, past the rules and in view of the censor.

- **Overlay:** dual-stack. IPv4 from `100.64.0.0/10`, plus a **random ULA /48 per space** (RFC 4193). Spaces have namespaces of their own, so overlapping IPv4 ranges on a shared node are harmless. Where the overlay's MTU is below IPv6's minimum of 1280, the overlay carries IPv4 only and the status says so.
- **Egress:** exits with IPv6 do NAT66; without it, IPv6 is blocked while connected. **Never leaked either way:** a device sends IPv6 into the TUN whenever the overlay carries it, and an exit without IPv6 refuses it there at once; with the overlay IPv4-only, the device's route table makes IPv6 unreachable; and either way the device's leak guard refuses IPv6 on the physical interfaces but to direct destinations, the entries and the direct DNS upstreams. The exceptions are the rows whose Breaks column names D6.
- **The leak guard** is a firewall owner of its own, applied with the routes and kept in place against other software (but RR11), and it stays when the agent dies, so IPv6 fails closed across a crash (but RR16). Its failure never fails the routes or a connect: it is reported and retried, and an OS that can't host it still connects, with a warning (RR10–RR12).
- **Everything is dual-stack:** route-table rules (GeoIP lists carry IPv6 ranges), DNS (`AAAA`), and the kill switch.
- **Entries reachable over IPv6** are extra candidate paths. Censors sometimes treat IPv6 differently, which deserves a lab module.

### Direct paths (hole punching)

A later candidate path, not a separate feature. Nodes learn their public endpoint from our own server nodes (never public STUN), try direct UDP, and keep the relay as the fallback. Under a whitelist, traffic between two home or mobile IPs may simply not get through. Direct paths reveal each device's real IP to the other and show the censor encrypted UDP between home IPs, so they are a per-space setting.

### Desktop client

Two processes. The **service** is the node agent: it runs privileged (TUN, routes, firewall), installed as a launchd daemon, systemd unit or Windows service. The **tray app** is unprivileged and talks to the service over a local socket (named pipe on Windows) with a small gRPC API (the local API, below). The CLI is a third client of the same API. Its UI stack is provisional (TP-086).

A device can be enrolled in several spaces but runs **one at a time**: switching spaces tears down one data plane and brings up the other.

When the entry in use belongs to another space, the tray labels it **`owned by <space>`**: that space's node owner can see the member's IP and traffic volume (see Trust in the PRD).

#### The local API

Status, connect and disconnect, spaces, rule presets and the in-memory log, for the CLI and the tray. Connect and disconnect bring a device's data plane up and down while the service keeps following its space's maps; a server serves whenever it runs.

- **Two gates.** The socket's directory admits only root, the service's user and one group; every call then checks the caller's kernel-recorded credentials: the group sees the status and controls the node, the log (whose debug lines may quote the map) is root's only. There is no read-only tier for other users (RR43).
- **The API never takes the VPN down.** If it can't serve, the node runs on without it, retrying.
- **A rule preset chosen through the API** is stored by the service and nothing else writes it; one that can't be read stops the node from starting rather than reading as "no rules".
- **Nothing the API reports is a public address, a key or a secret** (S1, S4): ids are opaque, addresses are the overlay's, failures are named from fixed vocabularies. Clients sanitize every string they receive before showing it.
- **`diag`** returns a versioned snapshot (its host parts, which name public addresses, are root's); see [`agent/localapi`](internal/agent/localapi/doc.go).

#### Kill switch

While on and the tunnel is down, the firewall (pf, nftables, Windows Filtering Platform) allows only traffic to entry nodes, plus LAN when allow-LAN is set. A pause option covers captive portals. The IPv6 leak guard is the connection's, not the kill switch. Not built yet (RR17).

**After a crash the device fails closed by default** under the "everything" and "all but domestic" presets (opt-out): the firewall's rules stay in place when the agent dies without disconnecting, so an unattended crash or failed update leaks nothing, and they come out when the agent starts again and connects. A crash is the likeliest mass-exposure event, and the member least able to notice it is the one who never touched a setting (PRD Decisions, "Crash posture"). A **deliberate disconnect** is different and follows the kill-switch toggle (off by default, D4): the guard comes out, and the traffic goes direct unless the toggle is on. macOS must meet this too. Until the kill switch exists (TP-048), IPv4 flows after a crash (RR18).

### Node safety

What a censor finds on a seized or inspected server node:

| On the node | What it holds |
|---|---|
| Binary and systemd unit | — |
| Keys | One key set per space served; private keys generated on the node, never copied off |
| Map | Only the node's own decrypted part per space (see the signed map): ids, endpoints and credentials of the links it serves. **No member names, no rules it doesn't enforce, no other nodes' credentials.** Devices appear as opaque ids (a device's own section names its peers, for its overlay names) |
| Logs | None written by the agent: they go to an in-memory ring that only root reads, through the local API. Under systemd, stderr reaches the journal, which provisioning is to make volatile (RR40) |
| Telemetry | Only in memory, per space, bounded (on the order of 15 minutes and tens of kilobytes); **each record sealed to the space's telemetry key as it's written**, so neither a memory dump nor swap yields readable data; oldest dropped first; gone on reboot |

On disk a node keeps its state directory: its keys, the space's public keys, the space's map, a device's rule choice, and public lists named by hash. It, and every directory above it, can be changed only by root or the node's user: whoever could replace the space's keys would choose the maps the node trusts, and whoever could replace the map could roll the node back (RR46). Workers can't read it; the supervisor hands them what they need. Outside it a node keeps only what it must find again after a crash, recorded so the next start undoes or takes it over: its locks, routes and leak guard, the OS's resolver configuration, on a server the supervisor's nftables tables and forwarding record, and on macOS route records, which name the entries' addresses, and a pf reference record (RR52).

Telemetry records are aggregates per link and per device id (rates, byte counts, path and transport in use, handshake failures), **never public IP addresses or destinations**. History lives only on the controller.

Later: **ephemeral nodes** keep nothing on disk but the binary. After a reboot they are blank, and the node owner's controller re-provisions them over SSH.

### Node agent

The data-plane engine is in-process wiring, configured by one call per map. It owns the ports it drives and imports no host adapter; everything around it is the agent's: following the space's maps, building the transports, running the listeners, and sequencing the host's adapters, which the composition root picks per OS.

- **One node agent per host.** Before anything of the node touches the host, the agent takes the host's agent lock, because a second agent's start-time cleanups would undo the running agent's routes and resolver configuration.
- **A removed node idles, it doesn't fail.** A valid newer map without a section for the node stops its data plane; the agent stays up following the space's maps and starts again when a later map includes it, and a node that finds itself removed at start starts idle the same way, rather than being restarted over and over by its service manager.
- **A device's connection is one state with its transitions** (PRD Decisions, "Agent modelling"): a move its state can't make is refused and logged as a bug. What happens to a node is told as typed events, once per edge, not on every retry that fails again.

### Control plane (the controller, on go-kernel)

Until a space has its controller (or instead of one, by choice), it runs hand-operated: [docs/runbook-pre-controller.md](docs/runbook-pre-controller.md) is the operating model of that period — maps built with the dev tooling (`dev map build`, `dev map rotate`), copied to servers over SSH and to devices by hand, restarts after reboots, binary updates, and chrony for the clock agreement the transports rely on.

A DDD service: CLI plus `thinkpol admin serve` for the web panel, reachable **only through the overlay**. That is a network control, not access control: members' devices are on the overlay by design, and the controller holds the space's signing key. How the panel is organised, authenticated and authorised is open (see Open questions); its canvas is planned in [`shared`](internal/shared/doc.go).

**Each admin runs their own controller**, managing that admin's spaces. The space's signing key lives there and nowhere else, so no one can sign another admin's map. Its default place is a server the admin owns **outside the censor's jurisdiction** (PRD Decisions, "Controller placement").

Everything is space-scoped: every aggregate carries its space id.

| Feature | Aggregates / responsibility |
|---|---|
| `spaces` | **Space**: name, signing public key, recovery public key, telemetry public key, IPv4 range, IPv6 ULA prefix |
| `members` | **Member**: role (`admin`, `member`), grants (which chains they may use, whether their devices are reachable space-wide) |
| `nodes` | **Node**: opaque id, display name (controller-only), owner member, kind (`server`, `device`), `allowIngress` and `allowEgress` (servers only, both default off), overlay addresses, WireGuard public key, offered transports and their credentials, camouflage target; **own** or **shared** (another space's node, used through a grant) |
| `hosting` | **HostingGrant**: shared node, guest space's public key, bandwidth cap, ingress and egress granted (at most what the node allows), state (`offered`, `accepted`, `revoked`). Offered and accepted as signed tokens passed out of band between the two admins, like invites |
| `topology` | **HopGroup**: members + selection policy. **Chain**: ordered hops (nodes or hop groups); invariants: hops distinct, first hop allows ingress, last hop allows egress (for a shared node: as granted to this space), and for a hop group every member does |
| `policy` | **RuleSet**: the space's default routing rules |
| `invites` | **Invite**: single-use, expiring join token carrying the space public key and the first node to contact; rendered as link and QR code. Redeeming one creates a **pending device**, not an active one (see Joining) |
| `provisioning` | Turning a fresh Linux box into a node over SSH, hardening included (volatile journald, no on-disk logs) |
| `publishing` | A projector: on any change, rebuild the space's map, bump its version, seal each node's part, sign, push out |
| `telemetry` | Ingests sealed node reports; 24 h rolling retention; node owners see per-space volume on their nodes, guests see only their own slice |

Events (`NodeJoined`, `NodeRemoved`, `MemberRemoved`, `GrantAccepted`, `GrantRevoked`, `ChainChanged`, `PolicyChanged`, `MapPublished`, `PathDegraded`, `TransportBlocked`) drive publishing and the dashboards.

#### The signed map

One per space: a signed envelope with a header (space id, key epoch, version, the space's signing and recovery public keys, hashes of list files) and **one sealed section per node**, sealed to that node's own map key. Each section holds only what its node needs: an entry, the devices it accepts with their credentials' verifiers, its links' settings and its forwarding table; an exit, the WireGuard keys and overlay addresses of devices allowed to use it; a device, its rules, chains, reachable peers with their candidate first hops, and entry endpoints.

- **The envelope links nothing to a node.** Sections carry no recipient id, and their count and length are padded and their order shuffled, so the envelope reveals neither which section is whose, nor a relay's from a device's or a dummy, nor how many nodes a space has (S6) beyond a size bucket (RR45).
- **Maps only move forward.** Versions only go up, ordered by **(key epoch, version)**; nodes accept a valid envelope with a higher version from anyone, including other nodes, so it spreads by gossip, but each can open only its own section. Rollback is impossible, and there is no expiry, so offline networks keep working. Revocation is a new version without the node.
- **Format changes never strand a node.** The format number and the header stay where format 1 has them, so any node can tell which space and version a newer envelope is; new fields are ignored by older nodes; fields they must not ignore roll out per section, each naming the lowest reader that understands it; **the format number is bumped only after the release that reads the new format has rolled out through format-1 maps**.
- **Recovery key.** Created with the space and kept offline by the admin (printed phrase or QR code); never on the controller. It can sign exactly one kind of record: "from key epoch N, the signing key is X", so a lost or stolen controller is recovered by rotating to a new key instead of re-creating the space; the epoch changes only that way, so a stolen signing key can't freeze the space by signing the highest possible version, and an old record can't roll the key back. Controller database backups are encrypted to the same key, so one thing kept offline restores everything (RR47).

**Shared nodes and maps.** The node owner's map tells the node which guest spaces it serves: each guest's space id, signing and recovery keys, cap, and the ingress and egress granted. The node then accepts the guest space's envelopes as well, but only for that guest's worker. Only the owner space's listeners are honored on a shared node; the supervisor reads each guest's inbound links from that guest's map to authenticate its connections. To the guest's controller, the shared node is an endpoint plus the grant, with nothing to provision.

#### Joining

- Server: `thinkpol node add root@192.0.2.10` installs the binary and a systemd unit, hardens logging, enables forwarding, configures nftables, has the node **generate its own keys**, adds it to the map with ingress and egress off, and publishes; `thinkpol node set <node> --ingress --egress` opens it up. Every step is idempotent, so re-running is how you repair a node.
- Device: `thinkpol join <invite>`. An invite travels through surveilled channels (chat apps, email), so holding a live one is not enough to join: redeeming it **creates a pending device**, which has registered its public keys and has **no section**, so it reaches nothing and learns nothing about the space. The admin **approves** it (panel or CLI), and approval publishes its section, which makes it a member's device. A pending device that isn't approved in time expires. The state is the one a removed device already has, a device the controller knows with no section in the map, so the map machinery needs nothing new.
- Sharing: the node owner runs `thinkpol grant offer <node> --ingress --cap 50mbit`, and the guest admin runs `thinkpol grant accept <token>`.
- Updates: signed release binaries, distributed through the network like list files. The update signing key is pinned on a server when it is provisioned over SSH, which is the anchor; a node whose update fails the signature check keeps running its current binary and never bricks.

#### Kernel usage

`config`, `app`, `observability`, `sqlite` and `webui` for the controller; `grpckit` for the push channel to nodes, whose streaming RPCs go through grpckit's stream interceptors like the local API's already do. The node agent uses `config`, `app`, `grpckit`, `ddd` (the local API's refusals) and `observability`. There is no DDD in the packet path, which is plain ports and adapters: packets aren't domain events.

**Protobuf contracts live in this repo** under `proto/`, buf-managed (the map format, the local service API, the controller's node API), never in go-kernel's `contracts/`. This is a deliberate thinkpol-only exception to the kernel convention of hosting consumers' contracts: these schemas are wire formats between thinkpol's own binaries, not contracts between separate services.

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

## Censor lab

The test suite, and the definition of "done" for a transport. Docker Compose with a client, a **censor** container between client and entry, an entry, an exit, an "internet" target and a real site for camouflage. Censor modules, each switchable:

- IP and SNI blocklists
- WireGuard and OpenVPN fingerprints
- fully-encrypted-traffic heuristics (as in *How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic*, USENIX Security 2023)
- active prober
- JA3/JA4 fingerprint filtering
- whitelist mode: everything whose destination address isn't listed is dropped first, then the name in the handshake is checked; UDP is dropped even to listed addresses; variants throttle the rest (to about 14 kb/s), reset it, or let it time out. A name-only check, still seen on some lines, is a separate, weaker module
- volume-based throttling

Besides censor modules, the lab runs two non-censor checks:
- **Isolation:** two spaces share an entry, and every attempt to reach across fails.
- **Seizure:** a snapshot of a node's disk and memory is searched for member IPs, names and destinations.

`make lab` runs every transport against every module and regenerates a pass/fail matrix committed as `lab/RESULTS.md`. A cell passes only when data crossed over IPv4 and IPv6, and a cell whose censor can't be trusted is an error, never a pass: the matrix is honest or not written.

## Milestones

Scope per milestone is in [PRD.md](PRD.md#release-plan); these are the technical "done" checks.

| | Milestone | Done when |
|---|---|---|
| M0 | Two Linux nodes in the lab, hand-made map in the sealed-section format, `udp` transport, relay paths; server agent as supervisor + one worker in its own namespace | `ping` directly (device ↔ server) and device ↔ device via a relay, over IPv4 and IPv6 ([lab/M0.md](lab/M0.md)) |
| M1 | Exit node with NAT, route-table rules with GeoIP, DNS, IPv6 handling, macOS and Linux CLI clients | on a real Mac: connect, rules, DNS and overlay names pass the device checklist; on Linux, the lab tests. On macOS the IPv6 guard loads and passes its own check on a device. Not proven on a device yet: RR9, RR15 |
| M2 | `reality` transport with probe fallback; lab v1 (blocklists, WireGuard fingerprint, entropy, prober); kill switch and connect-on-boot on macOS/Linux (TP-048, TP-046) | `udp` fails the lab, `reality` passes |
| M3 | Chains and hop groups with failover; lab whitelist mode | `ru-entries → nl-exit` passes the lab's whitelist mode through an allowlisted entry (the lab models one; obtaining one in the real world is not promised); killing the active entry keeps an open connection alive |
| M4 | Controller on go-kernel: spaces, members, invites, SSH provisioning with hardening, map gossip, hosting grants and shared nodes, telemetry, admin panel with canvas | a fresh box joins with one command and shows up on the canvas; a second space shares the entry and the isolation and seizure checks pass |
| M5 | Desktop client: service + tray app on macOS, Linux, Windows; tray toggles for kill switch and connect-on-boot; Windows kill switch and connect-on-boot; invite links; space switcher | a non-technical member joins from an invite without a terminal |

After the MVP: Android, userspace enforcement (domain rules), direct paths, tuned traffic shaping, `ws` behind a CDN, ephemeral nodes.

## Out of scope (for now)

VPS provider APIs (every node is a fresh Linux box you rent yourself), automatic IP rotation (needs provider APIs), onion-layered encryption across hops, iOS, our own crypto. Android is the first step after the MVP, so data-plane packages must stay buildable for mobile (no cgo, no desktop-only dependencies outside `tun`, `egress` and the firewall adapters).

After the MVP, considered and set aside (owner, 2026-10-18):

- **A member's device as an exit** (a home connection as the way out, e.g. for domestic services that refuse foreign addresses). Forwarding needs a worker, so only on Linux, and the node's own configuration should be able to limit it to domestic destinations: an exit inside a censoring country exposes its owner (PRD risks).
- **A device that offers its home network** (Tailscale's subnet routers). Home devices trust their LAN and a seized member device keeps valid credentials, so not a route into the LAN: a Linux node that offers named services (host and port), allowed in its own configuration, with the gateway, link-local, multicast and the node itself always refused, use narrowed per member by the map, and each connection logged.
- Both are capabilities the node's owner allows locally and the space's map can only narrow.

## Open questions

- **Admin panel: organisation, authentication and authorization.** The owner hasn't decided how the panel is organised, so none of this is designed: who may sign in, what each role may see and change, sessions, CSRF on the forms, what the canvas endpoint exposes. To be designed before TP-042 starts; overlay reachability is not access control.
