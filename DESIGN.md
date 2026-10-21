# thinkpol-vpn — Design

A self-hosted virtual network that survives a censor: your devices and VPS nodes form one private network (device ↔ device, device → exit node → internet), traffic between nodes is disguised by pluggable transports, and egress can be chained through several hops. The upkeep story Tailscale gets right — one command to join a node, keys and config handled for you — without its three problems: a WireGuard wire format the censor can block by protocol, clients depending on someone else's servers, and no chaining.

Built for taste, not for a deadline: every layer is a port with swappable adapters, so the interesting parts (transports, routing policy, path selection) stay easy to change. Product name **thinkpol-vpn**; the binary is **`thinkpol`** (split into `thinkpol-<role>` binaries only if a real need appears). Requirements, users and the release plan are in [PRD.md](PRD.md); this document is how.

This document is the model: what must stay true, and why. How each part does it (the mechanism, with its numbers, paths and OS details) is in the package docs (`doc.go`), each linked from the section it serves and listed in [Where the mechanism lives](#where-the-mechanism-lives). A change that moves an invariant changes this document; a change to mechanism changes the package doc next to the code.

## Threat model

The censor this is built against, and the feature that answers each technique:

| Censor technique | Answer |
|---|---|
| **DPI** — protocol fingerprints (WireGuard, OpenVPN), SNI and IP blocklists | WireGuard is never on the wire; links between nodes use **transports** that look like ordinary traffic |
| **Active probing** — connecting to a suspected server to see what answers | Transports authenticate before revealing anything; unauthenticated connections are forwarded to a real site (camouflage target) |
| **Profiling** — traffic shape, packet sizes and timing, TLS-in-TLS patterns, TLS fingerprints (JA3/JA4) | Browser-grade TLS fingerprints (uTLS); padding, batching and timing in the transport (the shaping contract; tuned by the lab) |
| **Whitelists** — only approved destinations reachable | **Chains**: the first hop is a whitelisted (typically domestic) VPS, which relays to a foreign exit. Disguise alone can't pass a whitelist. Whitelisted addresses are scarce, so **one entry serves several spaces**. Since 2026 the censor moves allowlisted services into subnets of their own, so a rented domestic VPS is almost never on the list: an allowlisted entry exists only where someone already controls an approved address. thinkpol uses one when it exists; it doesn't promise a way past whitelist mode without one. Under whitelist mode only TCP passes, even to listed addresses |
| **Seizure or inspection of a node** — in-country entries sit in the censor's jurisdiction | **Nodes know only what they need**: their own part of the map, opaque ids, no logs on disk, telemetry only in memory and sealed (see Node safety) |
| **Seizure or compromise of a member device** — it sits in the censor's jurisdiction and keeps its key on disk | Not prevented; bounded. The device holds valid credentials, so an entry can't tell the censor from the member, and nothing in telemetry detects it. Its section shows its entries' endpoints, its chains, rules and peer ids, and it reaches whatever the member could. **Per-device grants (A3)** bound the damage: only the chains and devices it was granted. **Revocation** is a new map without the device and spreads by gossip as soon as one honest entry is reachable |
| **Apps on a member's device** — government-affiliated apps that probe whether blocked services answer and look for VPN state: interfaces, routes, DNS, reachability | Partly hidden, honestly. Can't be hidden: a TUN (`utun`) interface and its routes are visible to every local app, so is the resolver's configuration, and a blocked service that answers shows that something carries it; Android's VpnService is detectable by design. What helps: "all but domestic" keeps domestic apps' traffic on the domestic path (not the interface or the routes). Per-app split tunnelling in userspace mode is the later mitigation (TP-065 researches what apps can observe) |

Not defended against: a censor that blocks everything foreign, a node owner abusing what an entry inherently sees (member IPs and traffic volume on its links) or running a modified binary (what the PRD says a node owner never sees holds for an owner running the honest one), and traffic analysis by a global observer. What remains inside the defended ground, leaks and windows accepted on purpose or until a named ticket, is listed in [Residual risks](#residual-risks).

## Rules

1. **WireGuard is the inner layer only.** It provides end-to-end crypto, per-peer routing and rekeying; it never touches the network directly. Everything it emits goes through the path layer and a transport.
2. **The controller is never a runtime dependency.** Configuration is a **signed network map**, not a live API. Nodes keep the last valid map indefinitely; with the controller switched off, the network keeps working and only stops changing.
3. **Chains are core, not an add-on.** A route to the internet is an ordered list of hops, chosen per destination by routing rules.
4. **No home-made crypto.** WireGuard (via wireguard-go), standard TLS, and NaCl-style sealed boxes. The project's own code decides *where* bytes go and *what they look like*, never how they are encrypted.
5. **Nodes know only what they need.** Every node can read only its own part of the map, and keeps nothing on disk it could do without.
6. **Spaces never touch.** On a shared node, each space gets its own network stack; nothing (packets, routes, DNS, telemetry) crosses between them.
7. **What can't be resolved fails closed.** Whatever a node doesn't know or can't do (a list not fetched, a matcher or a shaping field it doesn't understand, a preset the map can't build, a capability beyond its own ceiling) never widens what goes direct, what a transport reveals, or what the node does: it blocks, refuses or stays down, and says so in its health.

## Architecture

Two planes. The **data plane** moves packets on every node; the **control plane** decides what the network looks like and publishes it as the signed map.

### Data plane (every node, one binary)

```
 TUN ──► router ──► WireGuard ──► path layer ──► transport ──► wire
        (rules)    (per egress)   (conn.Bind)    (per link)
```

| Layer | Responsibility | First adapter |
|---|---|---|
| **TUN** | Virtual interface on macOS (utun), Linux, Windows (Wintun) | `wireguard-go/tun` ([`tun`](internal/dataplane/tun/doc.go)) |
| **Router** | Classifies each packet by destination: overlay peer, a chain, or `direct`. Holds the rule table (longest-prefix match on IPs) | in-process ([`router`](internal/dataplane/router/doc.go)) |
| **WireGuard** | End-to-end sessions with peers (devices, exits). Fed by the router through virtual `tun.Device`s — **one WireGuard device per egress**, because WireGuard routes by `AllowedIPs` and two exits would both claim `0.0.0.0/0` | `wireguard-go/device` ([`wg`](internal/dataplane/wg/doc.go)) |
| **Path layer** | A `conn.Bind`: WireGuard sees one stable peer; underneath, each peer has **candidate paths**, named by their first hop (relay N, or the peer itself; later direct UDP), and the layer picks and switches between them; relays route the rest of the way by destination | relay paths only ([`path`](internal/dataplane/path/doc.go)) |
| **Transport** | One link between two adjacent nodes; authenticates, frames packets, disguises the stream | plain UDP, the baseline the lab must catch ([`transport`](internal/dataplane/transport/doc.go), [`udp`](internal/dataplane/transport/udp/doc.go)) |

The engine ([`dataplane`](internal/dataplane/doc.go)) wires these for one space, configured by one call per map.

**Every server node relays; ingress and egress are opt-in.** Two node settings, both off by default: **allow ingress** (devices may connect, so the node can be a chain's first hop) and **allow egress** (internet traffic may leave from it, so it can be a chain's last hop). A node with both off accepts only other servers and only relays. There are no fixed roles: what a node does in a chain comes from its position there, so the same VPS can start one chain, sit in the middle of another and end a third. Device-to-device relaying needs a relay devices can reach, so it uses nodes that allow ingress.

**Relays, chains and device-to-device are one mechanism: destination routing.** A relay forwards opaque WireGuard packets by destination node id; it never decrypts them. Each relay's map section holds a forwarding table (per destination, the adjacent next hops); a sender knows only its candidate first hops per peer, so **no node holds a whole path**. Device-to-device through a relay is a first hop whose route delivers to the device; a chain `ru-entry → nl-exit` is the exit peer reached with `ru-entry` as first hop. A hop limit, capped by every relay, ends any routing loop a map contains.

**Hop groups make failover a path-layer decision.** A chain hop can be a group (`ru-entries`) with a selection policy: `failover` (priority order), `lowest-latency`, or `spread` (each device sticks to one member, devices are distributed). The path layer switches with hysteresis; links don't report liveness, so a link counts as up only while its own probes are answered. Through M2 failover follows those links alone, in priority order, and covers a node's own first-hop or next-hop link; scoring by handshakes, loss and latency, the other policies and the end-to-end probes that find a break further on come with hop groups (M3, TP-031). One end of each pair leads and the other follows its choice, so both ends use the same entry. WireGuard's session is with the exit, not the entry, so **switching entries keeps the exit and open connections survive**. No per-packet balancing across entries: packets would arrive out of order, which TCP handles badly. `spread` is the useful kind of balancing, and it also keeps any single entry IP's volume low against volume-based throttling.

#### Transports

Roughly in order of how hard they are to catch:

| Transport | Shape | Notes |
|---|---|---|
| `udp` | sealed datagrams | baseline; an hourly connection id and WireGuard's rhythm, trivially profiled; pads to buckets or at random if the link asks |
| `tls` | TLS 1.3 with a browser fingerprint (uTLS), probe fallback to a real site | later (after the MVP), for node-to-node links. The client's auth token rides in the ClientHello, so a server can tell its clients from probes before answering anything: probes are proxied whole to the real site and see its certificate. The node's own certificate comes from a pluggable certificate source (self-signed and pinned by the client first; ACME with a real domain is optional, since probes never see it) |
| `ws` | WebSocket over TLS | can sit behind a CDN, which hides the node's IP |
| `reality` | REALITY's handshake: a uTLS browser ClientHello whose session id seals the client's short id; failed auth is spliced to a real target site | the disguised transport for client → entry (M2, TP-087). Disguise comes from a borrowed real site: probes complete a handshake with the target and see its certificate; no certificate of our own. Credential: the device's short id, a shared secret; the listener holds an X25519 private key. Stock VLESS clients and servers are not supported (findings: TP-064) |
| `obfs-udp` | obfuscated datagrams | for direct device-to-device paths, where TCP hole punching is impractical |

Stream transports carry TCP inside TCP and degrade under loss; datagram transports are the first thing throttled under whitelists. Hence **transports are chosen per link**, not per network.

**Server-side tells.** uTLS covers the client and the camouflage site's certificate covers what a probe sees, but not the server's own hello: the worker terminates TLS with Go's stack, so its JA3S/JA4S, extension order and ALPN differ from the camouflage site's, a stable discriminator for a censor that fingerprints responses. A second tell: every probe makes the entry open an upstream connection to the camouflage target, which an ordinary server doesn't. Both are known weaknesses; the lab's prober measures them (TP-026, TP-032) and the matrix shows them honestly (RR31). `reality` (above) changes less than it seems: a probe is spliced to the target and gets its handshake byte for byte, as a probe proxied by `tls` did; an authenticated session's ServerHello is still ours (REALITY's stack, not the target's), so the first tell remains for a censor that compares members' sessions with the site's; and every failed probe still dials the target, the same upstream tell as `tls`'s proxying. What it removes is a certificate of our own to manage. The lab measures both tells for `reality` too. A "bridge" node type (a VLESS ingress routed into the overlay) was considered and set aside as too complex for now.

**The map says, the engine converts, the transport decides.** Each transport's settings are its own protobuf messages: the controller encodes them, the transport's adapter decodes them, and the map and everything between carry them as opaque bytes. The conversion from the map to the transport port lives in the engine, which checks every entry with the transport before using it. Endpoints in the map are IP literals: the controller resolves names, nodes never resolve them at dial time. Nodes' clocks must agree within five minutes.

**Transports own traffic shape.** WireGuard's fixed packet sizes and its rhythm (rekey every 2 minutes, keepalives) would show through any wrapper, and only the transport knows what traffic it's imitating. So padding, batching, timing and cover traffic are part of the transport contract (C6), and the layers above never pad; they only mark the packets that keep a link warm or measure it, so a transport can fold their rhythm into its own. The contract's invariants:

- **Per end, from the map, never negotiated:** each end shapes what *it* sends; receivers undo shaping from the wire format alone.
- **Refuse, never weaken:** an adapter refuses a link whose shaping it can't honour, and a node refuses shaping fields it doesn't know, rather than shape less than the map asks. Shaping sits inside the transport's encryption and never touches its authentication or replay protection.
- **Rollout:** refusing is safe only if the controller never asks a node for what it can't do. So the controller puts shaping (or a new shaping field or value) into a link only when both ends' nodes reported supporting it: agents report their version and transport/shaping capabilities when they register and when they update, and a link whose ends don't both support a shaping goes unshaped (or keeps the old shaping) until they do.

The contract's details (what can be asked, MTU budgeting, control packets) are in [`transport`](internal/dataplane/transport/doc.go) and [`shaping`](internal/shaping/doc.go). The lab measures how much shaping is enough per transport and tunes the defaults (none, until it says otherwise).

**Egress** is a Linux server's worker forwarding and masquerading its space's internet traffic (NAT66 for IPv6); a node in device mode never forwards, whatever its section says. A userspace TCP/IP stack is a later alternative. Mechanism: [`supervisor`](internal/agent/supervisor/doc.go), [`egress`](internal/dataplane/egress/doc.go).

### Server agent: one worker per space

Server nodes run a **supervisor** and **one worker process per space**, from M0 on, even while a node serves only one space. Mechanism: [`supervisor`](internal/agent/supervisor/doc.go), [`worker`](internal/agent/worker/doc.go), [`ipc`](internal/agent/ipc/doc.go).

- **Each worker lives in its own Linux network namespace** with its own TUN, WireGuard devices, routing table, firewall rules, resolver and per-space node keys. Spaces can't see each other's packets or routes because they don't share a network stack, not because code is careful. A crash in one space's worker leaves the others running.
- **Workers are sandboxed and tied to the supervisor.** A worker runs in a fresh user namespace whose root maps to an unprivileged host uid, so its network capabilities apply only inside its own namespaces; it keeps nothing else (a minimal root, no other capabilities, bounded resources), never outlives the supervisor, and talks to it only over two sockets. A crashed worker is restarted in a fresh namespace.
- **The root namespace keeps the spaces apart.** A worker owns its veth, so isolation can't rest on the spaces' routes: the supervisor's own firewall in the root namespace anti-spoofs each space to its own transit address before connection tracking sees it, and binds every accept to the space that owns the flow, so no space can reach another, or the root namespace, through it. Egress opens exactly what it masquerades.
- **The supervisor owns the public address**, the scarce resource. It accepts every incoming connection, runs the transport's authentication, maps the credential to a space, and hands the connection or datagram to that space's worker. Unauthenticated connections go to the camouflage target, so a probe sees one ordinary site whatever the number of spaces (not yet: no camouflage exists, and what fails authentication is dropped, so a `udp` listener is a silent port). The space a credential belongs to comes from the map it was listed in, never from what the map says. On a node with ingress off, the listener accepts only other servers' credentials, the node's address is never written into a device's section, and the node enforces that itself from its own section, whatever the map lists.
- **A worker answers its peers, never anyone else.** Its replies leave through the public socket only to addresses its space's own authenticated, fresh, non-replayed datagrams came from, recently; a worker can't use the node's public address to reach anyone else, whatever egress its space has. Replays are dropped before they reach a worker or cost its space anything: a replay needs only a passive tap.
- **Pre-authentication parsing moves out of the root supervisor.** Everything that parses unauthenticated bytes (the ClientHello peek, datagram authentication, timestamp and replay filtering) goes to an unprivileged **gatekeeper** process, sandboxed like a worker, with no space keys beyond what verification needs: a memory-safety bug in that path then costs the gatekeeper, not a root process holding every space's credential tables. The gatekeeper hands what it authenticates to the worker as the supervisor does today; the supervisor keeps the namespaces, the root firewall and fair share. For `tls` the credentials should be asymmetric (listeners verify with a public key), so a listener's holder can't forge a client; a symmetric transport (`udp`) still needs a secret per credential, and the gatekeeper is where it lives; a `reality` listener's gatekeeper holds the listener's X25519 private key (TP-088). Until it lands (TP-063 for `udp` in M2, TP-088 for `reality`, `tls`'s part with TP-028) the supervisor does all of this itself, which is the known weakness of the current design.
- **Stream transports** (`reality` in M2, `tls` after the MVP) authenticate in the ClientHello, in the legacy session id via uTLS: for `tls` the token is an HMAC of the credential and a coarse timestamp, checked by peeking at the ClientHello without terminating TLS, against a replay cache; for `reality` it is the short id and time sealed to the listener's key, and the connection is handed over once its TLS session is established. Authenticated: the connection's file descriptor and the bytes already read go to the space's worker (passed over a Unix socket); with `tls`, the worker terminates TLS with its own certificate, self-signed and pinned by the client. Anything else is proxied as a whole to the camouflage target, so a probe completes a handshake with the real site and sees its certificate.
- **A replayed ClientHello takes exactly the camouflage path.** A token already in the replay cache, one outside the timestamp window and one that doesn't verify are all the same thing, an unauthenticated connection: proxied whole to the camouflage target, with the same upstream connection and the same timing. A censor that captured a member's ClientHello and replays it learns nothing from the difference; dropping or resetting a replay instead would make replay an active-probing oracle. **The token window** is both the replay window (how long a captured ClientHello can be replayed at all, and how long the cache must remember a token) and the clock-skew margin (how far a client's clock may be off before it is locked out): a wider window means fewer outages and a longer replay opportunity, a narrower one the opposite. It starts at the five minutes nodes' clocks must already agree within, and the lab tunes it.
- **Bounded state.** Everything kept about unauthenticated or replayable traffic (replay windows, sender memories, routed streams, reply addresses) is bounded, so no peer can grow a node's state without limit, and a bound that is hit refuses (or sends to the camouflage) rather than forgets where forgetting would let a replay back in. Today `udp`'s memory of evicted senders forgets its oldest past its bound, an accepted residual. The bounds are in [`udp`](internal/dataplane/transport/udp/doc.go) and [`supervisor`](internal/agent/supervisor/doc.go). Replay protection doesn't survive a supervisor restart yet (TP-069). The `tls` replay cache holds a token only for the token window, and has a bound of its own that sends a connection to the camouflage when reached (TP-028).
- **The camouflage target is chosen per node**, not defaulted fleet-wide: one default shared by every node is a fingerprint of the fleet, and the target should be plausible for the node's address and network. Provisioning (TP-038) picks it and the documentation says it is security-relevant.
- **Egress** leaves each namespace through its own veth pair, and all spaces exit from the node's public IP. A space's traffic is capped in flows, refused to destinations no space should reach (metadata services, link-local and private networks, the transit ranges, unless the node names an exception), and accepted out of the uplink only for the families its map grants and the uplink carries. A worker's dials to the endpoints its own section lists leave the same way, whatever the egress; nothing else does without it. Forwarding the supervisor turns on is recorded and put back when no space needs it.
- **Fair share:** the supervisor enforces each guest space's bandwidth cap and splits spare capacity under load; a handed-over stream's bytes never pass through the supervisor, so its cap sits on the socket and the interface. Not yet: production builds pass no fair share to the supervisor, nor memory and pid limits to workers (TP-040, parked; TP-067).
- **The node's own configuration is a ceiling over the map.** What a machine may do is allowed on the machine, by whoever runs it: a preset, `device` (a member's device, nothing more) or `server`, and within `server` each capability on its own: ingress, egress (with its exceptions) and relaying; later, serving guest spaces and their caps. A fresh install is a device; anything more is opted into locally (provisioning does it with the operator's consent, TP-038), the way a Tailscale device advertises itself as an exit node before an admin can use it. The space's signed map acts within the ceiling and can never widen it. To a node, a map is two things: what the others are (peers, keys, revocations, routes), which it always takes from a newer signed map, and what this node is asked to do. At start, a map that asks this node for more than its ceiling leaves it down: health says why, and it carries no traffic. While running, it keeps its last accepted capabilities, takes the rest of the newer map, and reports the refusal; it saves only what it accepted, so a restart comes back to that. The same holds when the owner lowers the ceiling under a running map. Nodes need no agreement among themselves: to the space, a node that refuses a role is like one that is down, which hop groups route around (M3). With the controller (M4), nodes advertise their ceiling and the builder refuses to publish a map that asks for more; each node still enforces it, because a controller can be compromised. Not yet: the map's node kind and a `-mode` flag pick how a node runs (TP-111).
- **Node-level control** (agent updates, which spaces the node serves, caps) belongs to the **node owner**, the admin of the space that owns the node, within the node's ceiling. A guest space configures only its own worker, through its own map.

### Routing rules and DNS

An ordered rule list; first match wins:

```
domain-suffix:example.ru  → direct
geoip:ru                  → direct
geosite:youtube           → chain:de
default                   → chain:ru-nl
```

Actions: `direct`, `chain:<name>`, `block`. Matchers: `default`; `local` (the built-in local ranges, never the overlay's); `cidr:<prefix>`; `geoip:<list>`; and `domain:`, `domain-suffix:`, `geosite:`, kept in the map and enforced by DNS and, later, userspace mode. GeoIP alone misroutes CDNs (foreign services on domestic IPs and vice versa), so the rule format supports domains from day one even though enforcement comes later.

The space's default list lives in the signed map, in each device's section, with the chains it names and what the presets are built from (a domestic list and a chain). Each device can override it locally (the "what goes through the tunnel" switch): a base, the space's rules or a preset (**everything**, **all but domestic**), with the device's own rules ahead of it. Mechanism: [`rules`](internal/dataplane/rules/doc.go).

**Nothing unknown widens what goes direct.** The space's overlay networks are decided by peers, before any rule. A preset the map can't build fails closed, never back to the space's rules. A rule whose addresses aren't known (a list not fetched yet, a matcher the node doesn't know) matches nothing and turns off the `direct` rules after it; an unknown action, or a chain that can't carry traffic, blocks; a destination no rule matches is blocked. Rules don't raise the section reader: a node too old to know them routes nothing outside the overlay into the tunnel and keeps following the space's maps.

**Chains in use at the same time end at different exits.** WireGuard holds one session per exit and the path layer sends each exit's packets along one path at a time, so two chains to the same exit can't both carry traffic: they are alternatives, which a hop group expresses better. The map builder rejects a rule set that uses two chains ending at the same exit.

Two ways to enforce the same rules:

| Mode | How | Matches |
|---|---|---|
| **Route table** (first) | Install `direct` IP ranges as OS routes to the physical gateway, everything else into TUN | IP only (`geoip`, `cidr`); domain rules are skipped with a warning |
| **Userspace** (later) | Everything enters TUN; a userspace TCP/IP stack opens each connection itself, `direct` or tunneled | IP, domain (DNS interception, SNI), per app |

#### Route table

What route-table mode guarantees, on every OS (mechanism: [`routetable`](internal/dataplane/routetable/doc.go), [`netcfg`](internal/dataplane/netcfg/doc.go), [`ifbind`](internal/dataplane/ifbind/doc.go)):

- **Only the rules decide what bypasses the tunnel**: the direct destinations and the links' own endpoints. No route another party adds (a DHCP server's classless routes, TunnelVision, CVE-2024-3661; a public subnet a network declares on-link, TunnelCrack's LocalNet; another VPN's routes; a route into the overlay's range) takes tunnelled traffic around the tunnel. A local network is trusted only where it lies inside the local ranges *and* the rules send it direct. The cost, accepted: hosts on a public on-link LAN go through the tunnel unless the rules send them direct.
- **The links bypass the tunnel by their sockets** (a firewall mark on Linux, a binding to the physical interface on macOS), and their endpoints are routed around it too, so a link never loops into its own tunnel and nothing names the gateway where the OS lets us avoid it: roaming needs no change.
- **What the TUN can't take meets an unreachable route**, never the physical interface: IPv6 when the overlay doesn't carry it, the overlay's own networks always, and both families while the TUN is down.
- **Direct shrinks before the router changes and grows after**, so a rule change never sends a tunnelled destination direct, even for a moment.
- **Everything we install is ours by mark and record**, so a restart after a crash takes it over and a stop removes it, and nothing of other software is touched.
- **Sockets the routing table can't hold** (bound to an interface, or routed by source address) are the firewall's: the IPv6 leak guard confines them now, IPv4 waits for the kill switch (TP-048).
- **The table is kept in place**: it is re-applied whenever links, addresses or routes change and periodically, and the health says when it isn't enforced.

Linux uses policy routing and has no window for a foreign route. macOS has no policy routing: routes compete by prefix length alone, so the tunnel's routes are split halves and more specific shadows of whatever foreign routes cover tunnelled destinations; a new foreign route wins until the watcher re-applies, and a foreign host route can't be outranked at all, only counted. Both are residual risks.

#### DNS

**DNS is routing.** A resolver on the node's overlay address answers overlay names (`<device>.<space>.internal`; `.internal` is reserved for private use, so a space name can never shadow a real domain), sends `direct` names to a domestic upstream, and everything else through the tunnel to a resolver at the exit. No DNS leaks, and GeoIP isn't fed CDN answers from the wrong country. Mechanism: [`dns`](internal/dataplane/dns/doc.go).

- **A name goes where its rule sends it**: the device's effective rule list read by name, with the same fail-closed rules as the route table. A name's rule picks only the upstream; the answer's addresses are routed by the address rules like any other. A tunnel-bound query leaves through the tunnel or not at all.
- **Names stay inside the space.** Overlay names are in devices' sections only, so a server holds no member names, and a device names exactly the peers it has now. Nothing under `.internal` and no reverse name of the overlay is ever forwarded; forwarded queries carry none of the client's EDNS options.
- **Answers never cross routes**: they are cached per route and the cache is flushed on every map or rule change, so a direct upstream's answer is never served for a name that goes through the tunnel.
- **Upstreams.** An exit asks public resolvers, not the host's: on most clouds the host's sit on private or link-local addresses, which the worker's egress refuses, and widening it would open the provider's network, metadata services included, to every space. An upstream the egress refuses is named in health, never silently dropped.
- **The OS resolves through the node while it is connected**, and gets its own configuration back when the device disconnects, stops or restarts after a crash. Where the OS can't be made to (another link's domains, another VPN's resolvers, settings made by hand), it is never assumed: the device's health says `dns_not_protected` and `thinkpol connect` says so while the tunnel stays up.
- **Nothing is logged about a query**: no names or answers in any log or on disk; the resolver keeps counters only.

The CNAME leak (a `direct` name aliased into a tunnel-bound name is resolved whole by the domestic upstream) is accepted; see Residual risks.

#### Lists

GeoIP lists (from v2fly geoip or DB-IP Lite files; geosite has a blob kind but no importer yet) are blobs the map references by content hash: one list per blob in a canonical encoding, so the same addresses always give the same hash. They are built from files the operator downloads (no third-party data lives in the repo) and distributed between peers inside WireGuard: nodes never fetch from outside the network. A node uses a blob only once it matches the map, and replaces a list in use only once its successor is verified. Servers serve only blobs a signed map of their space listed, so they are no oracle beyond that set. Mechanism: [`lists`](internal/lists/doc.go), [`blobs`](internal/dataplane/blobs/doc.go).

### IPv6

The risk is leaking: if the local network has IPv6 and the tunnel doesn't carry it, apps connect around the tunnel, past the rules and in view of the censor.

- **Overlay:** dual-stack. IPv4 from `100.64.0.0/10`, plus a **random ULA /48 per space** (RFC 4193). Spaces are isolated in their own namespaces, so overlapping IPv4 ranges on a shared node are harmless. The overlay's MTU is what links leave after transport, path header and WireGuard; where that is below IPv6's minimum of 1280, the overlay carries IPv4 only and the node's status says so. It is meant to be space-wide, computed by the map builder (TP-030); the budget is in [`dataplane`](internal/dataplane/doc.go).
- **Egress:** exits with IPv6 do NAT66; without it, IPv6 is blocked while connected. **Never leaked either way:** a device sends IPv6 into the TUN whenever the overlay carries it, and an exit without IPv6 refuses it there at once; with the overlay IPv4-only, the device's route table makes IPv6 unreachable; and either way the device's **leak guard** refuses IPv6 on the physical interfaces but to direct destinations, the entries and the direct DNS upstreams.
- **The leak guard** is a firewall owner of its own (an nftables table on Linux, a pf anchor on macOS), applied with the routes and kept in place against other software; it stays when the agent dies (fail closed for IPv6). Its failure never fails the routes or a connect: it is reported (`ipv6_guard_not_enforced`, retried; `ipv6_guard_unsupported` where the OS can't host it) — a decision not to fail closed on kernels without nf_tables. On macOS it is not yet proven on a device (TP-096). Mechanism: [`firewall`](internal/dataplane/firewall/doc.go).
- **Everything is dual-stack:** route-table rules (GeoIP lists carry IPv6 ranges), DNS (`AAAA`), and the kill switch.
- **Entries reachable over IPv6** are extra candidate paths. Censors sometimes treat IPv6 differently, which deserves a lab module.

### Direct paths (hole punching)

A later candidate path, not a separate feature. Nodes learn their public endpoint from our own server nodes (never public STUN), try direct UDP, and keep the relay as the fallback. Under a whitelist, traffic between two home or mobile IPs may simply not get through. Direct paths reveal each device's real IP to the other and show the censor encrypted UDP between home IPs, so they are a per-space setting.

### Desktop client

Two processes. The **service** is the node agent: it runs privileged (TUN, routes, firewall), installed as a launchd daemon, systemd unit or Windows service. The **tray app** is unprivileged and talks to the service over a local socket (named pipe on Windows) with a small gRPC API: connect/disconnect, status, space switcher, rule presets, kill switch, connect-on-boot. The CLI is a third client of the same API. The tray app's UI stack is provisional (TP-086).

A device can be enrolled in several spaces but runs **one at a time**: switching spaces tears down one data plane and brings up the other.

When the entry in use belongs to another space, the tray labels it **`owned by <space>`**: that space's node owner can see the member's IP and traffic volume (see Trust in the PRD).

#### The local API

gRPC on a Unix socket (a named pipe on Windows, TP-047): status, a status stream, connect and disconnect, the enrolled spaces, rule presets, and the agent's in-memory log. Connect and disconnect bring a device's data plane up and down while the service keeps running and keeps following its space's maps; a server serves its spaces whenever it runs and refuses them. Mechanism: [`localapi`](internal/agent/localapi/doc.go).

- **Two gates.** The socket's directory admits only root, the service's user and one group (`thinkpol`); every call then checks the caller's kernel-recorded credentials: the group sees the status and controls the node, the log (whose debug lines may quote the map) is root's only. There is no read-only tier for other users.
- **The API never takes the VPN down.** If it can't serve, the node logs it and runs on without it, retrying.
- **A rule preset chosen through the API** is stored by the service in the device's state directory and nothing else writes it; one that can't be read stops the node from starting rather than reading as "no rules".
- **Nothing the API reports is a public address, a key or a secret** (S1, S4): ids are opaque, addresses are the overlay's, failures are named from fixed vocabularies. Clients sanitize every string they receive before showing it.

#### Kill switch

While on and the tunnel is down, the firewall (pf, nftables, Windows Filtering Platform) allows only traffic to entry nodes, plus LAN when allow-LAN is set. A pause option covers captive portals. Not yet on any OS (TP-048); the IPv6 leak guard is the connection's, not the kill switch.

**After a crash the device fails closed by default** under the "everything" and "all but domestic" presets (opt-out): the firewall's rules stay in place when the agent dies without disconnecting, so an unattended crash or failed update leaks nothing, and they come out when the agent starts again and connects. Leaving that open is the opposite of what the threat model asks for: a crash is the likeliest mass-exposure event, and the member least able to notice it is the one who never touched a setting. A **deliberate disconnect** is different and follows the kill-switch toggle (off by default, D4): the guard comes out, and the traffic goes direct unless the toggle is on. macOS must meet this too, not only Linux and Windows (TP-019, TP-046, TP-048). Until then, IPv4 flows after a crash and IPv6 stays blocked but for direct destinations (Residual risks).

### Node safety

What a censor finds on a seized or inspected server node:

| On the node | What it holds |
|---|---|
| Binary and systemd unit | — |
| Keys | One key set per space served; private keys generated on the node, never copied off |
| Map | Only the node's own decrypted part per space (see the signed map): ids, endpoints and credentials of the links it serves. **No member names, no rules it doesn't enforce, no other nodes' credentials.** Devices appear as opaque ids (a device's own section names its peers, for its overlay names) |
| Logs | None on disk. Agent logs go to an in-memory ring, readable only by root through the local API; provisioning sets journald to volatile storage |
| Telemetry | Only in memory, per space, bounded (on the order of 15 minutes and tens of kilobytes); **each record sealed to the space's telemetry key as it's written**, so neither a memory dump nor swap yields readable data; oldest dropped first; gone on reboot |

On disk there is the state directory and nothing else: the node's keys (written once, when it is provisioned), the space's public keys (what every map is verified against), the space's map (delivered by hand until the node writes the maps it takes, TP-037), a device's rule choice, and public lists named by hash. It and every directory above it can be changed by no one but root or the node's user, since whoever could replace the space's keys would choose the maps the node trusts, and whoever could replace the map could roll the node back at its next start. A server's workers can't read it: the supervisor hands them what they need. Outside it, a connected device changes only the OS's resolver configuration and its own routes, each recorded so it is put back after a crash. Mechanism: [`agent`](internal/agent/doc.go).

Telemetry records are aggregates per link and per device id (rates, byte counts, path and transport in use, handshake failures), **never public IP addresses or destinations**. History lives only on the controller.

Later: **ephemeral nodes** keep nothing on disk but the binary. After a reboot they are blank, and the node owner's controller re-provisions them over SSH.

### Control plane (the controller, on go-kernel)

Until a space has its controller (or instead of one, by choice), it runs hand-operated: [docs/runbook-pre-controller.md](docs/runbook-pre-controller.md) is the operating model of that period — maps built with the dev tooling (`dev map build`, `dev map rotate`; [`devmap`](internal/devmap/doc.go)), copied to servers over SSH and to devices by hand, restarts after reboots, binary updates, and chrony for the clock agreement the transports rely on.

A DDD service: CLI plus `thinkpol admin serve` for the web panel, reachable **only through the overlay**. That is a network control, not access control: members' devices are on the overlay by design, and the controller holds the space's signing key. How the panel is organised, authenticated and authorised is open (see Open questions).

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
| `invites` | **Invite**: single-use, expiring join token carrying the space public key and the first node to contact; rendered as link and QR code. Redeeming one creates a **pending device**, not an active one (see Joining) |
| `provisioning` | Turning a fresh Linux box into a node over SSH, hardening included (volatile journald, no on-disk logs) |
| `publishing` | A projector: on any change, rebuild the space's map, bump its version, seal each node's part, sign, push out |
| `telemetry` | Ingests sealed node reports; 24 h rolling retention; node owners see per-space volume on their nodes, guests see only their own slice |

Events (`NodeJoined`, `NodeRemoved`, `MemberRemoved`, `GrantAccepted`, `GrantRevoked`, `ChainChanged`, `PolicyChanged`, `MapPublished`, `PathDegraded`, `TransportBlocked`) drive publishing and the dashboards.

**Admin panel.** Server-rendered with go-kernel's `webui` (htmx) for lists, forms and dashboards. The **canvas** (nodes, links, transports, chains as paths, live health and traffic on top, editing by dragging) is a JavaScript island on its page, a graph-editor library fed by a JSON endpoint and a live-update stream. Shared nodes appear on a guest's canvas as read-only, labelled `owned by <space>`. Whether islands like this belong in `webui` itself is a kernel question this project answers. Provisional: the admin panel and the client apps get separate frontends, and both stacks are revisited in TP-086.

#### The signed map

One per space: a signed envelope with a header (space id, key epoch, version, the space's signing and recovery public keys, hashes of list files) and **one sealed section per node**, sealed to that node's own map key. Each section holds only what its node needs:

- an entry gets the device ids it accepts, the transport's verifier for each one's credential (a hash or public key where the transport allows, the shared secret for a symmetric transport), per-link transport settings, and its forwarding table
- an exit gets the WireGuard keys and overlay addresses of devices allowed to use it
- a device gets rules, chains, reachable peers with their candidate first hops, and entry endpoints

Mechanism: [`netmap`](internal/netmap/doc.go).

- **The envelope links nothing to a node.** Sections carry no recipient id (a node finds its own by trying to open each one), and their count and length are padded and their order shuffled, so the envelope reveals neither which section is whose, nor whether one is a relay's or a device's or a dummy, nor how many nodes a space has (S6) beyond a size bucket.
- **Maps only move forward.** Versions only go up, ordered by **(key epoch, version)**; nodes accept a valid envelope with a higher version from anyone, including other nodes, so it spreads by gossip, but each can open only its own section. Rollback is impossible, and there is no expiry, so offline networks keep working. Revocation is a new version without the node.
- **Format changes never strand a node.** Every format keeps the format number and the header where format 1 has them, so any node can tell which space and version a newer envelope is; new fields are ignored by older nodes; fields they must not ignore are rolled out per section, each naming the lowest reader that understands it; **the format number is bumped only after the release that reads the new format has rolled out through format-1 maps**.
- **Recovery key.** Created with the space and kept offline by the admin (printed phrase or QR code); never on the controller. The header carries its public key, and it can sign exactly one kind of record: "from key epoch N, the signing key is X". Nodes accept that record over the current signing key and move to the new epoch, so a lost or stolen controller is recovered by rotating to a new key instead of re-creating the space; the epoch changes only that way, so a stolen signing key can't freeze the space by signing the highest possible version, and an old record can't roll the key back. Controller database backups are encrypted to the same key, so one thing kept offline restores everything. Not yet: the envelope still rejects any epoch change and recovery records (TP-036).

**Shared nodes and maps.** The node owner's map tells the node which guest spaces it serves: each guest's space id, signing and recovery keys, cap, and the ingress and egress granted. The node then accepts the guest space's envelopes as well, but only for that guest's worker. Only the owner space's listeners are honored on a shared node; the supervisor reads each guest's inbound links from that guest's map to authenticate its connections. To the guest's controller, the shared node is an endpoint plus the grant, with nothing to provision.

#### Joining

- Server: `thinkpol node add root@1.2.3.4` installs the binary and a systemd unit, hardens logging, enables forwarding, configures nftables, has the node **generate its own keys**, adds it to the map with ingress and egress off, and publishes; `thinkpol node set <node> --ingress --egress` opens it up. Every step is idempotent, so re-running is how you repair a node.
- Device: `thinkpol join <invite>`. An invite travels through surveilled channels (chat apps, email), so holding a live one is not enough to join: redeeming it **creates a pending device**, which has registered its public keys and has **no section**, so it reaches nothing and learns nothing about the space. The admin **approves** it (panel or CLI), and approval publishes its section, which makes it a member's device. A pending device that isn't approved in time expires. The state is the one a removed device already has, a device the controller knows with no section in the map, so the map machinery needs nothing new.
- Sharing: the node owner runs `thinkpol grant offer <node> --ingress --cap 50mbit`, and the guest admin runs `thinkpol grant accept <token>`.
- Updates: signed release binaries, distributed through the network like list files. The update signing key is pinned on a server when it is provisioned over SSH, which is the anchor; a node whose update fails the signature check keeps running its current binary and never bricks.

#### Kernel usage

`config`, `app`, `observability`, `sqlite` and `webui` for the controller; `grpckit` for the push channel to nodes, whose streaming RPCs go through grpckit's stream interceptors like the local API's already do. The node agent uses `config`, `app`, `grpckit`, `ddd` (the local API's refusals) and `observability` ([`agent`](internal/agent/doc.go)). There is no DDD in the packet path, which is plain ports and adapters: packets aren't domain events.

**Protobuf contracts live in this repo** under `proto/`, buf-managed (the map format, the local service API, the controller's node API), never in go-kernel's `contracts/`. This is a deliberate thinkpol-only exception to the kernel convention of hosting consumers' contracts: these schemas are wire formats between thinkpol's own binaries, not contracts between separate services.

## Residual risks

What the design accepts, on purpose or until a named ticket: leaks, windows and unprotected cases inside the defended ground of the [Threat model](#threat-model). Each row is a promise's exception: a change that removes one deletes its row, and a change that adds one adds a row here with its owner. PRD R4 (no DNS leaks) holds except for rows RR1–RR11, and D6 (no IPv6 leaks) except for RR12–RR17.

| # | Residual | When | What leaks, to whom | Why accepted | Owner |
|---|---|---|---|---|---|
| | **DNS** | | | | |
| RR1 | The CNAME | A `direct` name whose answer aliases into a tunnel-bound name | The domestic upstream resolves the whole chain, so it learns the target name (the target's addresses are still routed by the rules) | Inherent in forwarding. Resolving the tail through the tunnel hides it, but costs a second lookup per alias and splits one answer between two resolvers | [`dns`](internal/dataplane/dns/doc.go); TP-020 |
| RR2 | DNS not protected | Linux: a resolved domain or `~.` on another link (NetworkManager adds `~.`); macOS: DNS set by hand, `/etc/resolver`, another VPN's resolvers; any OS: pointing the OS fails | Names under those domains (all names, for a shared `~.`) go to that resolver, in the censor's view | Checked, never assumed: health `dns_not_protected`, `connect` returns an error while the tunnel stays up | [`dns`](internal/dataplane/dns/doc.go); TP-020, TP-019; NetworkManager: TP-046 |
| RR3 | Resolvers that bypass the OS | iCloud Private Relay, encrypted-DNS profiles, an app's own DoH | Names never reach the node's resolver, so name rules don't apply; the packets are still routed by the address rules | Outside the system resolver; nothing on the node sees them | TP-019 |
| RR4 | Re-override windows | Another program changes the OS's DNS. Linux: resolved's links are checked every 5 s, resolv.conf is taken back at once (2 s poll as backstop); macOS: 100 ms after configd's notification, 30 s backstop (2 s while unwatched) | Names may go to that program's resolver until the node takes the OS back | Watching, not locking, the OS's configuration | [`dns`](internal/dataplane/dns/doc.go); macOS captures TP-085 |
| RR5 | Stale direct upstreams | A read of the OS's resolvers fails (in-place writers of resolv.conf included) | Direct names keep going to the previous network's resolver | The OS still resolves through the node; health `dns_upstreams_stale` | [`dns`](internal/dataplane/dns/doc.go); TP-108, TP-115; TP-117 |
| RR6 | Per-link DNS on interface-bound sockets | Linux: systemd-resolved's per-link queries over IPv4 | They leave by the physical default route, to the link's resolver | IPv4's interface-bound sockets are the kill switch's | TP-048 |
| RR7 | LLMNR and mDNS | Single-label and `.local` names, on the physical links (Linux; macOS's mDNSResponder) | Multicast on the LAN | Local names stay local; turned off on the TUN's link only | TP-020 |
| RR8 | Plain DNS | Direct upstreams (devices) and the public resolvers (exits) | An on-path attacker can answer a direct query first; an exit's tunnel-bound queries cross the exit's network in the clear, and the public resolver sees them from the exit's address | No DoT or DNSSEC yet | none yet |
| RR9 | A server's section run as a device | `-mode device` on a section that allows egress | It answers names like an exit, asking the host's resolvers, its tunnel queries not bound to the TUN | The mode flag predates the node's ceiling | TP-111 |
| RR10 | A name rule undercut by an address rule | Route-table mode: `domain → chain`, and a later address rule sends the answer's addresses direct | The flow, its SNI included, goes around the tunnel | Domain enforcement needs userspace mode; reported in status | [`rules`](internal/dataplane/rules/doc.go); PRD R8 |
| RR11 | No DNS-leak proof on macOS | macOS | Unproven: the device captures so far couldn't have failed | Evidence gap | TP-085 |
| | **IPv6** | | | | |
| RR12 | No guard without nf_tables | Linux kernel without nf_tables | IPv6 from interface-bound sockets leaves the physical interface | Decision: connect anyway, with health `ipv6_guard_unsupported` | [`firewall`](internal/dataplane/firewall/doc.go); TP-021 |
| RR13 | Guard repair windows | Linux: the guard's table changed from outside, about 1 s; macOS: pf changed from outside, about 10 s (states made meanwhile live until the next good apply); either: the guard failing, until a retry (5 s) works | Interface-bound IPv6 may leave meanwhile | nftables' events, pf's lack of them; routes stay enforced | [`firewall`](internal/dataplane/firewall/doc.go); TP-021, TP-078 |
| RR14 | No pf hook | macOS: a main ruleset without `anchor "com.apple/*"` (replaced, or not loaded yet at boot), a `pass quick` above the hook, one inside an anchor evaluated before it | Interface-bound IPv6 unconfined; health says unsupported or not enforced (the nested anchor isn't seen) | As RR12; `/etc/pf.conf` is never edited | [`firewall`](internal/dataplane/firewall/doc.go); boot race: TP-046 |
| RR15 | What pf can't express | macOS | MLD-typed ICMPv6 to any multicast group with any hop limit (root only); ND to a DNS upstream's address may be forwarded; DNS to each direct upstream's address and port passes for any socket | pf has no hop-limit match and no socket mark | [`firewall`](internal/dataplane/firewall/doc.go); TP-078 |
| RR16 | Another VPN holds `::/1` | macOS, after a crash | Our reject route can't be added; IPv6 may leave by that VPN | Crash-time only | TP-019 |
| RR17 | No IPv6 proof on macOS | macOS with native IPv6 | Unproven that the guard blocks its leak paths | Evidence gap | TP-096 |
| | **IPv4 and the kill switch** | | | | |
| RR18 | No kill switch | Tunnel down, any OS | Traffic goes direct | Not built | TP-048; Windows TP-076 |
| RR19 | IPv4 after a crash | Linux and macOS, the agent died connected | All IPv4 in the clear until the next start; IPv6 stays blocked | Against the decided posture ([Kill switch](#kill-switch)) until it lands | TP-048, TP-046 |
| RR20 | IPv4 when the TUN drops | Linux | IPv4 follows the physical default route for a debounce (about 200 ms) until the unreachable default is in | An earlier reject route would answer the kernel's gateway lookups | [`routetable`](internal/dataplane/routetable/doc.go); TP-057 |
| RR21 | A device removed or retrying | Its map removed it, or a start failed and is being retried | Its data plane and routes are down, so its traffic goes direct | No kill switch | TP-048 |
| RR22 | Interface-bound IPv4 | Linux: `SO_BINDTODEVICE`, `IP_UNICAST_IF`, `IP_PKTINFO`; macOS: `IP_BOUND_IF`, sockets routed by source address | They leave by the physical interface (`ping -I`, connectivity checks) | The leak guard is IPv6 only | TP-048 |
| RR23 | Foreign routes on macOS | A new on-link subnet or classless route (TunnelVision, LocalNet), until the watcher re-applies (a debounce); a foreign host route, always | Tunnelled destinations go out the physical interface (IPv6 to them: the guard's) | No policy routing; a host route can't be outranked, only counted (`policy_rules_ahead`) | [`routetable`](internal/dataplane/routetable/doc.go); TP-019 |
| RR24 | Policy rules ahead of ours | Linux, other software's rules before the tunnel's | They may route around the tunnel | Reported (`policy_rules_ahead`) | [`routetable`](internal/dataplane/routetable/doc.go); TP-018 |
| RR25 | Endpoint throws | Any OS | Any app's traffic to an entry's address goes direct; behind a CDN that would be every site on the address | To narrow per flow when CDN transports come | [`routetable`](internal/dataplane/routetable/doc.go); `ws` |
| RR26 | Scoped route to a DNS upstream | macOS, a direct upstream off the link | Any socket bound to the physical interface reaches that address around the tunnel | An unscoped route would take everyone's traffic | [`routetable`](internal/dataplane/routetable/doc.go); TP-019 |
| RR27 | Local ranges always direct | Any preset | LANs, link-local and multicast bypass the tunnel; hosts on a public on-link LAN are tunnelled instead | A LAN is local; a public LAN opt-in later | [`rules`](internal/dataplane/rules/doc.go); TP-015, TP-057 |
| RR28 | No rules, or a reader too old | A section without rules or one its node can't read | Nothing outside the overlay goes through the tunnel | M0 compatibility | [`rules`](internal/dataplane/rules/doc.go); TP-015 |
| RR29 | A failed shrink | Removing direct prefixes fails and so does the fallback to nothing direct | Destinations the new rules tunnel still go direct until an Apply works | Retried every 5 s, reported | [`routetable`](internal/dataplane/routetable/doc.go) |
| | **Transports and probing** | | | | |
| RR30 | `udp` is the only transport | Today | Timing (rekeys, keepalives), sizes (no padding by default), a constant 8-byte connection id per hour and the 5-tuple link a node's flows; a probe meets a silent port, since no camouflage exists | The baseline the lab must catch | [`udp`](internal/dataplane/transport/udp/doc.go); TP-087 |
| RR31 | Server-side tells | `reality`, `tls` | The server hello differs from the camouflage site's; every failed probe dials the target, which sees each probe | Measured, not removed | TP-026, TP-032 |
| RR32 | A fleet-wide camouflage target | Until targets are chosen per node | One target shared by the fleet fingerprints it | Per node with provisioning | TP-038 |
| RR33 | Whitelist mode | No allowlisted entry | Nothing passes; UDP fails even to listed addresses | Not promised | PRD Decisions |
| | **Replay** | | | | |
| RR34 | Replay after a restart | A `udp` listener or the supervisor restarts | A passive tap's datagrams of the last 5 minutes (10 if the sender's clock ran ahead) open a link once more, and a fresh WireGuard device answers a replayed initiation: an active-probing oracle | A receiver's memory is per process | TP-069 |
| RR35 | A held datagram, a quiet sender | An on-path attacker, `udp` | A link opens toward the attacker until it dies, or the reply address moves once the real sender is quiet for 30 s, until its next datagram | Recovering at once after a clock step beats a 30 s outage | [`udp`](internal/dataplane/transport/udp/doc.go); TP-070 |
| RR36 | Evicted senders forgotten | More than 1024 evictions on one credential | An old sender can take over again once the current one is quiet | Making them takes the credential | [`udp`](internal/dataplane/transport/udp/doc.go) |
| | **Servers** | | | | |
| RR37 | Pre-authentication parsing as root | Every server, until the gatekeeper | A memory-safety bug there exposes every space's credential tables | Planned (Server agent) | TP-063, TP-088, TP-028 |
| RR38 | No resource limits, no fair share | A server shared by spaces | One space can starve another: memory, pids, bandwidth, the shared socket; each may fill a quarter of conntrack | Parked | TP-067, TP-040 |
| RR39 | `-egress-allowed` and metadata services | An exit whose operator allows them | Every space reaches the provider's credentials | The operator's choice; decision open | TP-118 |
| RR40 | Logs on disk | A server not provisioned yet | journald keeps the agent's stderr; debug lines may quote the map | Provisioning makes the journal volatile | TP-038 |
| RR41 | What nodes inherently see | Entries, relays, exits | An entry: member IPs and volume; an exit: destinations and names; a relay: node ids, sizes, timing; a symmetric `udp` link's listener could forge its dialer; a modified binary: what it handles | Not defended (Threat model); disclosed with `owned by` | TP-049; gatekeeper credentials |
| RR42 | A namespace thread | A server's netlink handle opened in a space's namespace | A thread could return to the scheduler inside that namespace | Judged not to happen in practice | TP-054 |
| | **Devices** | | | | |
| RR43 | Apps see the VPN | Any OS | The TUN, its routes, the resolver configuration, and which blocked services answer | Can't be hidden | TP-065 |
| RR44 | Device seizure | A member's device in the censor's hands | Its key, its section (entries, chains, rules, peer ids), its own rules and which lists it uses | Bounded by grants and revocation | PRD A3; TP-037 |
| RR45 | The local API's group | Members of the `thinkpol` group | They connect, disconnect and change presets; on macOS, members added since login or past 16 groups are refused (fails closed) | By design | [`localapi`](internal/agent/localapi/doc.go); TP-094 |
| RR46 | A second agent without the host lock | Linux under systemd's `RuntimeDirectory=`; Windows, Android | A second `up` can put the OS's DNS back under a live tunnel | The lock's directory comes with the service install | TP-046, TP-047 |
| | **The map** | | | | |
| RR47 | Envelope metadata | Every holder of an envelope | The list hashes (which public lists the space uses), the header (space id, version, keys), the section count's bucket | Accepted | [`netmap`](internal/netmap/doc.go), [`blobs`](internal/dataplane/blobs/doc.go) |
| RR48 | Rollback through the disk | Until nodes write the maps they take | Whoever can write `map.bin` chooses the map a node starts with | Owner-only files | TP-037 |
| RR49 | No key rotation | A stolen signing key | It can't be rotated away, and maps never expire | Recovery records not built | TP-036 |
| RR50 | A break past the first hop | Until end-to-end probes | The peer's traffic is lost, with no failover | Failover follows a node's own links | TP-031 |

## Repository layout

Follows go-kernel's service structure for the control plane; the data plane is its own tree of ports and adapters.

```
cmd/thinkpol/             # one binary: node agent / client service (`up`), CLI, `admin serve`, dev tools; one file per command
cmd/thinkpol-tray/        # unprivileged tray app, a client of the local service API
internal/
  agent/                  # the node agent on servers and devices: applies maps, runs the data plane, local API, service install, self-update
    supervisor/           # servers: owns the public address and the shared listener, starts one worker per space
    worker/               # servers: one space's data plane inside its own (user-namespaced) network namespace
    ipc/                  # supervisor<->worker protocol over SOCK_SEQPACKET (control + data, SCM_RIGHTS)
    logring/              # in-memory, bounded agent/worker log ring (no logs on disk, S2)
    localapi/             # the local service API on a Unix socket: server, peer-credential policy, client, renderers
  dataplane/              # the engine: owns its ports, wires router, wg, path and transport; the agent adapts the rest
    tun/ router/ wg/ path/
    rules/                # routing rules: presets, the device's local file, compilation into prefixes
    transport/            # the transport port; adapters in transport/<name>/
    netcfg/               # interface addresses, MTU, routes, policy rules
    routetable/           # route-table rule enforcement on top of netcfg; the link sockets' mark (Linux) or interface binding (macOS)
    ifbind/               # binds sockets to an interface (SO_BINDTODEVICE, IP_BOUND_IF)
    trusteddir/           # opens directories no one but root or the node's user can change; locks, reads and atomically replaces files in them
    nsthread/             # runs a function on an OS thread inside another namespace and moves the thread back
    firewall/             # IPv6 leak guard, kill switch (pf, nftables, WFP)
    egress/ dns/
    blobs/                # fetch-by-hash distribution of list files and releases between peers
    telemetry/            # node side of TP-041: per-space in-memory ring, sealed per record (not yet)
  netmap/                 # the signed map: envelope, sealed sections, signing, verification, gossip
  lists/                  # GeoIP/geosite lists: importers, CIDR aggregation, the content-addressed blob format
  shaping/                # the rules of the map's shaping message, shared by netmap's builder and the transport port
  devmap/                 # development tooling until the controller: maps from a hand-written YAML spec, dev key files (`dev keygen`, `dev map`)
  features/               # control plane bounded contexts (spaces, members, nodes, hosting, topology, policy, invites, provisioning, publishing, telemetry); no code in the root
    <feature>/adapters/http/   # that feature's admin panel pages
  shared/                 # shared/domain, shared/ports, shared/infra as in go-kernel; no code in the root
    infra/webui/          # the admin panel's page shell: layout, navigation, assets, the canvas island
proto/                    # buf module: the map format, the local service API, the controller's node API
  gen/                    # generated Go code, never hand-edited
lab/                      # censor lab (below)
```

- **OS specifics** are per-OS files (`_linux.go`, `_darwin.go`, `_windows.go`) inside the package they belong to; there is no separate platform tree.
- **Lists** are built offline (`thinkpol dev lists build`, later the controller), distributed by `dataplane/blobs`, and read by the rules (`dataplane/rules`), which the router enforces. `lists` sits outside `dataplane` because both planes use it.
- **Dependency direction**: `dataplane`, `netmap`, `lists` and `agent` never import `features` or `shared`; `dataplane`, `netmap` and `lists` never import `agent`; `dataplane`, `netmap` and `lists` don't import go-kernel; `features` never import `dataplane` or `agent`, nor each other (cross-feature calls go through `shared/ports`); `shared` never imports `features`. The planes meet only through the signed map.
- **Mobile**: everything under `dataplane`, `netmap` and `lists` is pure Go; all of it except `tun`, `egress` and `firewall` builds for Android.

### Engine and agent

The data-plane engine (`dataplane.Engine`) is in-process wiring, configured by one call per map. It owns the ports it drives (the overlay interface's configuration, the route table's want and status, what the resolver serves) and holds only what it means by them; `netcfg`, `routetable` and `dns` know nothing of those ports, and the agent adapts them, so the engine's own files import none of `dataplane/netcfg`, `dataplane/routetable`, `dataplane/dns` and `dataplane/tun` (depguard). Everything around the engine is the agent's: following the space's maps and applying each, building the transport registry, running the listeners, and sequencing the host's adapters, which the composition root (`cmd/thinkpol`) picks per OS and hands over. `routetable` never imports `firewall`: the leak guard is a port of the route table that the agent fills.

- **One node agent per host.** Before anything of the node touches the host, the agent takes the host's agent lock, so a second agent can't undo the first one's start-time cleanups.
- **A removed node idles, it doesn't fail.** A valid newer map without a section for the node stops its data plane; the agent stays up following the space's maps and starts again when a later map includes it, and a node that finds itself removed at start starts idle the same way, rather than being restarted over and over by its service manager.
- **A device's connection is one state with its transitions** (PRD Decisions, "Agent modelling"): a move its state can't make is refused and logged as a bug. What happens to a node is told as typed events, each once the status shows it and once per edge, not on every retry that fails again.

Mechanism: [`agent`](internal/agent/doc.go), [`dataplane`](internal/dataplane/doc.go).

### Where the mechanism lives

| Topic | Package doc |
|---|---|
| Engine, MTU budget | [`dataplane`](internal/dataplane/doc.go) |
| Node agent: maps, modes, host lock, connection states, events, state directory, go-kernel usage | [`agent`](internal/agent/doc.go) |
| Local API: socket, gates, limits | [`agent/localapi`](internal/agent/localapi/doc.go) |
| Supervisor: isolation tables, shared listeners, reply addresses, egress, forwarding | [`agent/supervisor`](internal/agent/supervisor/doc.go) |
| Worker sandbox | [`agent/worker`](internal/agent/worker/doc.go), [`agent/ipc`](internal/agent/ipc/doc.go) |
| Destination routing, liveness, failover | [`dataplane/path`](internal/dataplane/path/doc.go) |
| Transport port, shaping contract | [`dataplane/transport`](internal/dataplane/transport/doc.go), [`shaping`](internal/shaping/doc.go) |
| `udp`: wire format, replay rules, bounds | [`dataplane/transport/udp`](internal/dataplane/transport/udp/doc.go) |
| Rules: matchers, presets, compilation | [`dataplane/rules`](internal/dataplane/rules/doc.go) |
| Route table on Linux and macOS | [`dataplane/routetable`](internal/dataplane/routetable/doc.go), [`dataplane/netcfg`](internal/dataplane/netcfg/doc.go), [`dataplane/ifbind`](internal/dataplane/ifbind/doc.go), [`dataplane/trusteddir`](internal/dataplane/trusteddir/doc.go) |
| IPv6 leak guard (nftables, pf) | [`dataplane/firewall`](internal/dataplane/firewall/doc.go) |
| Resolver, OS DNS on Linux and macOS | [`dataplane/dns`](internal/dataplane/dns/doc.go), [`dataplane/router`](internal/dataplane/router/doc.go) |
| Lists and their distribution | [`lists`](internal/lists/doc.go), [`dataplane/blobs`](internal/dataplane/blobs/doc.go) |
| The map's envelope and sections | [`netmap`](internal/netmap/doc.go), [`devmap`](internal/devmap/doc.go) |
| Censor framework | [`lab/censor`](lab/censor/doc.go), [lab/README.md](lab/README.md) |

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

`make lab` runs every transport against every module and regenerates a pass/fail matrix committed as `lab/RESULTS.md`. A cell passes only when data crossed over IPv4 and IPv6, and a cell whose censor can't be trusted is an error, never a pass: the matrix is honest or not written. The censor (`censord`, TP-024) judges every forwarded packet with the modules a test picks and logs every decision; modules register themselves, and new transports join by adding a probe. Mechanism: [`lab/censor`](lab/censor/doc.go).

## Milestones

Scope per milestone is in [PRD.md](PRD.md#release-plan); these are the technical "done" checks.

| | Milestone | Done when |
|---|---|---|
| M0 | Two Linux nodes in the lab, hand-made map in the sealed-section format, `udp` transport, relay paths; server agent as supervisor + one worker in its own namespace | `ping` directly (device ↔ server) and device ↔ device via a relay, over IPv4 and IPv6 ([lab/M0.md](lab/M0.md)) |
| M1 | Exit node with NAT, route-table rules with GeoIP, DNS, IPv6 handling, macOS and Linux CLI clients | on a real Mac: connect, rules, DNS and overlay names pass the device checklist; on Linux, the lab tests. On macOS the IPv6 guard loads and passes its own check on a device. Not yet proven on a device: that the guard blocks its leak paths (TP-096) and that DNS doesn't leak (TP-085) |
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
