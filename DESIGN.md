# thinkpol-vpn — Design

A self-hosted virtual network that survives a censor: your devices and VPS nodes form one private network (device ↔ device, device → exit node → internet), traffic between nodes is disguised by pluggable transports, and egress can be chained through several hops. The upkeep story Tailscale gets right — one command to join a node, keys and config handled for you — without its three problems: a WireGuard wire format the censor can block by protocol, clients depending on someone else's servers, and no chaining.

Built for taste, not for a deadline: every layer is a port with swappable adapters, so the interesting parts (transports, routing policy, path selection) stay easy to change. Product name **thinkpol-vpn**; the binary is **`thinkpol`** (split into `thinkpol-<role>` binaries only if a real need appears). Requirements, users and the release plan are in [PRD.md](PRD.md); this document is how.

## Threat model

The censor this is built against, and the feature that answers each technique:

| Censor technique | Answer |
|---|---|
| **DPI** — protocol fingerprints (WireGuard, OpenVPN), SNI and IP blocklists | WireGuard is never on the wire; links between nodes use **transports** that look like ordinary traffic |
| **Active probing** — connecting to a suspected server to see what answers | Transports authenticate before revealing anything; unauthenticated connections are forwarded to a real site (camouflage target) |
| **Profiling** — traffic shape, packet sizes and timing, TLS-in-TLS patterns, TLS fingerprints (JA3/JA4) | Browser-grade TLS fingerprints (uTLS); padding, batching and timing in the transport (the shaping contract; tuned by the lab) |
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
| **Path layer** | A `conn.Bind`: WireGuard sees one stable peer; underneath, each peer has **candidate paths**, named by their first hop (relay N, or the peer itself; later direct UDP), and the layer picks and switches between them; relays route the rest of the way by destination | relay paths only |
| **Transport** | One link between two adjacent nodes; authenticates, frames packets, disguises the stream | plain UDP (the baseline the lab must catch) |

**Every server node relays; ingress and egress are opt-in.** Two node settings, both off by default: **allow ingress** (devices may connect, so the node can be a chain's first hop) and **allow egress** (internet traffic may leave from it, so it can be a chain's last hop). A node with both off accepts only other servers and only relays. There are no fixed roles: what a node does in a chain comes from its position there, so the same VPS can start one chain, sit in the middle of another and end a third. Device-to-device relaying needs a relay devices can reach, so it uses nodes that allow ingress.

**Relays, chains and device-to-device are one mechanism: destination routing.** A relay forwards opaque WireGuard packets by destination node id; it never decrypts them. Each packet carries a small header {destination, source, hop limit} inside the transport's seal. The source tells the destination's path layer which peer, and so which WireGuard device, a packet is for, and gives WireGuard an endpoint it can answer; relays drop packets from sources they don't know (no route to it, not adjacent), and already see these ids as destinations of the replies. The check is loose because routes needn't be symmetric yet; once the map builder makes them so, it can become a strict reverse-path check. The hop limit, capped by every relay, ends any routing loop the maps contain. Each relay's map section holds a **forwarding table**: per destination, the adjacent next hops (several for a hop group in the middle of a chain). A sender knows only its **candidate first hops** per peer (adjacent entries, or the peer itself for a direct link), and each relay only its next hop, so no node holds a whole path. Device-to-device through a relay is a first hop whose route delivers to the device; a chain `ru-entry → nl-exit` is the exit peer reached with `ru-entry` as first hop, which routes to `nl-exit`. Candidate first hops and next hops are listed in **priority order**, which is what `failover` follows.

**Hop groups make failover a path-layer decision.** A chain hop can be a group (`ru-entries`) with a selection policy: `failover` (priority order), `lowest-latency`, or `spread` (each device sticks to one member, devices are distributed). At the start of a chain the group becomes the device's candidate first hops, one per member; in the middle, a relay's next hops toward the exit. The path layer scores them (handshake success, loss, latency) and switches with hysteresis. Links don't report liveness, so both ends probe each link, and a link counts as up only while its own probes are answered. Through M2, failover covers the failure of a node's own first-hop (or next-hop) link: the switch comes within about one dead interval (6 s) of the last answered probe. A path that breaks further on is found only by end-to-end probes of each path, which come with hop groups (M3). One end of each pair follows the other: the lower node id leads, and the higher takes whichever entry the leader's latest authenticated packet came through (the endpoint WireGuard adopts names it), on the next packet it sends, and never returns to its own first choice on its own. Relays in the middle keep one next hop per destination and fail over on their own links. WireGuard's session is with the exit, not the entry, so **switching entries keeps the exit and open connections survive**. No per-packet balancing across entries: packets would arrive out of order, which TCP handles badly. `spread` is the useful kind of balancing, and it also keeps any single entry IP's volume low against volume-based throttling.

**Transports** (roughly in order of how hard they are to catch):

| Transport | Shape | Notes |
|---|---|---|
| `udp` | sealed datagrams | baseline; an hourly connection id and WireGuard's rhythm, trivially profiled; pads to buckets or at random if the link asks |
| `tls` | TLS 1.3 with a browser fingerprint (uTLS), probe fallback to a real site | the workhorse for client → entry. The client's auth token rides in the ClientHello, so a server can tell its clients from probes before answering anything: probes are proxied whole to the real site and see its certificate. The node's own certificate comes from a pluggable certificate source (self-signed and pinned by the client first; ACME with a real domain is optional, since probes never see it) |
| `ws` | WebSocket over TLS | can sit behind a CDN, which hides the node's IP |
| `reality`-style | borrows a real site's TLS handshake, no certificate of our own | later |
| `obfs-udp` | obfuscated datagrams | for direct device-to-device paths, where TCP hole punching is impractical |

Stream transports carry TCP inside TCP and degrade under loss; datagram transports are the first thing throttled under whitelists. Hence **transports are chosen per link**, not per network.

**The map says, the engine converts, the transport decides.** Each transport's settings (listener, dial side, inbound side) are its own protobuf messages in `proto/thinkpol/transport/v1/`: the controller encodes them, the transport's adapter decodes them, and the map and everything between carry them as opaque bytes. The conversion from the map to the transport port's types lives in the data-plane engine (`internal/dataplane`), not in `netmap` or the adapters; it checks each entry with the transport before using it. Endpoints in the map are IP literals: the controller resolves names, nodes never resolve them at dial time. Transports may rely on clocks: nodes' clocks must agree within five minutes (`udp` drops datagrams sealed further from its own clock).

**Transports own traffic shape.** WireGuard's fixed packet sizes and its rhythm (rekey every 2 minutes, keepalives) would show through any wrapper, and only the transport knows what traffic it's imitating. So padding, batching and timing are part of the transport contract; the layers above never pad. The contract (`transport.Shaping`, encoded as `thinkpol.transport.v1.Shaping`):

- **What can be asked:** padding of each wire unit (datagram or record) to size buckets or by a random amount in a range, a batching window, timing jitter, idle cover traffic. Sizes are what a capture sees.
- **Per end, from the map:** each end of a link shapes what *it* sends: the map's endpoint carries the dialing end's shaping, its inbound link the listening end's, in a `shaping` field next to the transport's settings; the engine decodes it and the adapter checks it. Receivers undo shaping from the wire format alone, so nothing is negotiated and the two ends needn't agree.
- **Refuse, never weaken:** an adapter refuses a link whose shaping it can't honour, and a node refuses shaping fields it doesn't know, rather than shape less than the map asks. Padding and cover sit inside the transport's encryption, so they never touch its authentication or replay protection. The message's rules live in `internal/shaping`, which both the map's builder (it never publishes shaping no node could read) and the transport port use.
- **Rollout:** refusing is safe only if the controller never asks a node for what it can't do. So the controller puts shaping (or a new shaping field or value) into a link only when both ends' nodes reported supporting it: agents report their version and transport/shaping capabilities when they register and when they update, and the controller keeps the newest report per node. A link whose ends don't both support a shaping goes unshaped (or keeps the old shaping) until they do.
- **MTU:** `Overhead(shaping)` is the fixed per-packet cost plus the most random padding adds; under bucket padding a packet that fits the path can still round up past it, so the path layer budgets WireGuard's MTU with `transport.MaxPacket(transport, shaping, unit)`.
- **Control packets:** the layers above mark packets that only keep a link warm or measure it (probes, keepalives) with `transport.WriteControl`, so a transport can fold their rhythm into its own (pad and jitter them like data, hold one up to 500 ms to ride with data or cover, or send it as cover). WireGuard's handshakes and data never go that way. A round trip timed with control packets, or through batching or jitter, is an upper bound: liveness can rest on it, latency comparisons are made on unheld traffic (e.g. WireGuard's handshake round trip).

`udp` implements padding and refuses the rest; the lab measures how much is enough per transport and tunes the defaults (none, until it says otherwise).

**Egress** (nodes that allow egress, Linux): IP forwarding + nftables masquerade (NAT66 for IPv6), in a server's worker namespace and the root namespace (see "Server agent"). Only a worker is an exit: its engine writes what peers send for the internet to its TUN (the router's `Local` check relaxed on the overlay device), while a node in device mode never forwards, whatever its section says. A userspace TCP/IP stack is a later alternative.

### Server agent: one worker per space

Server nodes run a **supervisor** and **one worker process per space**, from M0 on, even while a node serves only one space:

- **Each worker lives in its own Linux network namespace** with its own TUN, WireGuard devices, routing table, nftables rules, DNS resolver and per-space node keys. Spaces can't see each other's packets or routes because they don't share a network stack, not because code is careful. A crash in one space's worker leaves the others running.
- **Workers are sandboxed processes tied to the supervisor.** A worker is `thinkpol worker` started by the supervisor in a fresh **user namespace** with its own network, mount, PID, IPC, UTS and cgroup namespaces, with the parent-death signal set, so it never outlives the supervisor and its namespace dies with it. The user namespace maps the worker's root to an unprivileged host uid per slot, so its capabilities (`NET_ADMIN` for its data plane, `NET_RAW`, `NET_BIND_SERVICE`) apply only inside its own namespaces and can't reach the root namespace through the veth's link-netnsid. Before serving it `pivot_root`s into a minimal tmpfs (a handful of `/dev` nodes, empty `/run` and `/tmp`, and no `/proc` or `/sys` — the data plane uses netlink and the supervisor sets the space's network sysctls by entering its namespace), clears its supplementary groups, drops `CAP_SYS_ADMIN` and everything but the network capabilities, sets `no_new_privs`, and is bounded by a per-worker cgroup (memory, pids; rlimits where cgroup v2 isn't available). It talks to the supervisor over two unnamed `SOCK_SEQPACKET` sockets: a control socket (config, lifecycle, stream handoff) and a data socket (forwarded datagrams, sent non-blocking so a stuck worker drops them). A crashed worker is restarted with backoff, in a fresh namespace.
- **The root namespace keeps the spaces apart.** A worker owns its veth, so isolation can't rest on the spaces' routes: the supervisor's nftables tables, in the root namespace, drop everything forwarded to a space's veth but replies to its own flows, anti-spoof each space to its own transit address before conntrack sees its packets, bind every accept to the slot that owns the conntrack entry (by the entry's original-direction address: a space's flows started from its transit address, the root's flows with a space went to it), take no "related" packet from a space into the root namespace itself, and drop a space's ARP and ND (permanent neighbour entries on both veth ends make them unnecessary) so they can't flood the root neighbour table. Anti-spoof and the binding are what isolate: conntrack takes an ICMP error as related to whichever flow it quotes, so a space forging one about another space's flow, or a root flow, gets that flow's entry, which no accept of its own matches. Per-space conntrack zones, for what a space exchanges with its end of the veth pair, are belt and braces. Egress opens exactly what it masquerades.
- **The supervisor owns the public address**, the scarce resource. It accepts every incoming connection, runs the transport's authentication, maps the credential to a space, and hands the connection to that space's worker. Unauthenticated connections go to the camouflage target, so a probe sees one ordinary site whatever the number of spaces. On a node with ingress off, the listener accepts only other servers' credentials (a device's is unauthenticated, so it gets the camouflage), and the node's address is never written into a device's map section, so no device can leak it. The map builder writes no link between such a node and a device, in either direction, and no address of it into a device's section under any node id; the node enforces the rule itself too, from its own section (`dataplane.AcceptedInbound`), whatever inbound links the section lists. The supervisor merges the spaces' credential tables, stamping each entry's space from the map it came from, never from what the map says.
  - **Datagram transports** carry a keyed connection id that tells the supervisor which credential to check; it authenticates each datagram, checks its timestamp and filters replays per credential (the transport's own sender windows) before forwarding it, untouched, to the worker over the worker's data socket, without blocking (a full socket drops the datagram, so a stuck worker stalls only its own space). A replay needs only a passive tap to capture, so it is dropped before it reaches a worker or costs its space anything. The worker decrypts and filters again; a space's fair-share bucket is charged once the worker's socket accepts a datagram. The worker's replies come back over the same socket and leave through the public socket, charged too, but **only to a source address that one of the space's own authenticated, fresh, non-replayed datagrams came from, through that listener, in the last ~2 minutes**: each link keeps its latest few such addresses, so no link can displace another's. A worker can answer its peers, never use the node's public address to reach anyone else, whatever egress its space has.
  - **Stream transports** (`tls`) authenticate in the ClientHello: the token (an HMAC of the credential and a coarse timestamp, in the legacy session id via uTLS) is checked by the supervisor, which keeps a replay cache, by peeking at the ClientHello without terminating TLS. Authenticated: the connection's file descriptor and the bytes already read go to the space's worker (passed over a Unix socket), which terminates TLS with its own certificate, self-signed and pinned by the client. Anything else is proxied as a whole to the camouflage target, so a probe completes a handshake with the real site and sees its certificate.
- **Egress** leaves each namespace through its own veth pair: the space's namespace forwards (only with egress, by its table) and SNATs the overlay range to its transit address, at a fully random port in 32768–60999, and the root namespace masquerades the transit ranges within that range (listeners can't bind there), so all spaces exit from the node's public IP. The uplink is the supervisor's: the interface of the root namespace's default route, found again on every change of the spaces and of the routes; a space's grant (`Space.Egress`, the families its map allows) counts in the families the uplink carries (IPv6 only with a global address: unique local is no internet). In the root table a space's traffic is capped in flows (a quarter of the conntrack table by default), refused to destinations no space reaches (metadata services, link-local and private networks, the transit ranges; `EgressAllowed` names exceptions, such as a network that is the node's internet), then accepted out of the uplink per family granted, and only for its own flows; replies come back as established flows bound to the space's transit address. Forwarded flows share the root's conntrack zone 0, since replies arriving on the uplink must find them. A worker's dials to the endpoints its own section lists (other servers: relays, chains) leave the same way, by the uplink and in their transport's protocol, whatever the egress; nothing else does without it. A transit source about to leave unmasqueraded is dropped. A family the uplink lacks is refused inside the space's namespace with ICMP "no route", so clients fall back at once instead of timing out. Where the root namespace doesn't forward, the supervisor turns forwarding on (first setting `accept_ra` 2 where it is 1, so IPv6 forwarding doesn't cost an RA-configured uplink its default route), forwards nothing but the spaces' traffic, records what it changed in `/run/thinkpol` for a successor, and puts it back (side effects included, each only if unchanged since) when no space needs it and on `Close`. Other tables' drops still win (a container runtime's or a host firewall's `FORWARD` policy): provisioning's concern.
- **Fair share:** the supervisor enforces each guest space's bandwidth cap (token buckets per space, or tc classes per veth) and splits spare capacity under load. The shared listener's datagrams go through a per-space hook (asked before forwarding or sending, charged after). A handed-over stream's bytes never pass through the supervisor, so its cap sits elsewhere: a pacing rate set on the socket before the handoff limits only what the node sends on it; uploads need policing (tc ingress, or an IFB device) or a read-rate limit.
- **Node-level control** (agent updates, which spaces the node serves, caps) belongs to the **node owner**, the admin of the space that owns the node. A guest space configures only its own worker, through its own map.

### Routing rules and DNS

An ordered rule list; first match wins:

```
domain-suffix:example.ru  → direct
geoip:ru                  → direct
geosite:youtube           → chain:de
default                   → chain:ru-nl
```

Actions: `direct`, `chain:<name>`, `block`. Matchers: `default`; `local`, the built-in local ranges (LANs, link-local, multicast, broadcast; never `100.64.0.0/10`, the overlay's range); `cidr:<prefix>` (IPv4 is matched only as IPv4, so an IPv6 prefix around `::ffff:0:0/96`, such as `::/0`, leaves that range out); `geoip:<list>`, a GeoIP blob the node's section names; and `domain:`, `domain-suffix:`, `geosite:`, kept in the map and enforced by DNS and, later, userspace mode.

The space's default list lives in the signed map, in each device's section, with the chains it names (name → exit; at M1 a chain is its exit node) and what the presets are built from (a domestic list and a chain). The builder requires the list to end with `default`. Each device can override it locally (the "what goes through the tunnel" switch): a local file (`rules.local` in the state directory, written only by the service through the local API) picks a base, either the space's rules or a preset (**everything**: `local → direct`, `default → chain:<c>`; **all but domestic**: also `geoip:<domestic> → direct` after `local`), and the device's own rules go ahead of it. A preset the map can't build fails closed, never back to the space's rules: "all but domestic" without a domestic list is "everything", and without a chain only `local` goes direct and the rest is blocked. Rules don't raise the section reader: a node too old to know them ignores them and routes nothing outside the overlay into the tunnel, as on M0, and keeps following the space's maps and their revocations.

**Rules compile to prefixes.** The space's overlay networks are decided first, by peers, whatever the rules say. The rest compiles into a longest-prefix table: per address family a `/0` route for the action with the most prefixes, and every other action's prefixes, which never overlap (RU's "all but domestic" is ~22k routes, the size of the list). Whatever a node can't resolve never widens what goes direct: domain rules match no address in route-table mode; a rule whose addresses aren't known (a list not fetched yet, an unknown matcher) matches nothing and, unless it was `direct` itself, turns off the `direct` rules after it; an unknown action, or a chain whose exit isn't a usable peer, blocks; a destination no rule matches is blocked; with no rules at all, nothing goes through the tunnel. The exit of each chain some rule uses gets a WireGuard device of its own, allowed the internet but, of the overlay, only the exit's own addresses.

**Chains in use at the same time end at different exits** (here `de` and `nl`). WireGuard holds one session per exit and the path layer sends each exit's packets along one path at a time, so two chains to the same exit can't both carry traffic: they are alternatives, which a hop group expresses better. The map builder rejects a rule set that uses two chains ending at the same exit.

Two ways to enforce the same rules:

| Mode | How | Matches |
|---|---|---|
| **Route table** (first) | Install `direct` IP ranges as OS routes to the physical gateway, everything else into TUN. Merge adjacent CIDRs; country lists are thousands of prefixes, and Windows is slow with big tables | IP only (`geoip`, `cidr`); domain rules are skipped with a warning |
| **Userspace** (later) | Everything enters TUN; a userspace TCP/IP stack opens each connection itself, `direct` or tunneled | IP, domain (DNS interception, SNI), per app |

**Route table on Linux** (`dataplane/routetable`): policy routing, per family. Rule 5300 looks up the main table only for the overlay's networks and the subnets the physical interfaces reach on-link (the kernel's routes for their addresses, mirrored as `to <prefix>` rules; only local ranges, or IPv4 /24 and IPv6 /64 or longer, so a huge DHCP netmask gets nothing past the tunnel). No other route in main, such as a DHCP server's classless routes (TunnelVision, CVE-2024-3661), another VPN's split defaults or a router advertisement's routes, comes before the tunnel. Rule 5301 sends every packet without the links' firewall mark (0x7470) to a table of its own (0x7470): a default route into the TUN, an `unreachable` default behind it (IPv4 and IPv6), and a `throw` route per direct prefix and per link endpoint. Thrown and marked packets go on to the main table and its physical default route, so nothing names the gateway: DHCP and roaming need no change. Whatever the TUN can't take (it is down, gone, or carries no IPv6) meets the unreachable default: dropped, never sent around the tunnel. The agent re-applies when a link comes, goes or changes state (a TUN going down takes its IPv4 route along without telling anyone), when an interface's on-link routes or a default route change, when its own routes or rules are removed, every minute anyway, and every 5 s while that fails; the status says when the table isn't enforced, and when other software's policy rules come first. The transports' sockets carry the mark (`SO_MARK`, set by the transport adapter, never by WireGuard), and the endpoints' throws keep links out of the tunnel even without it (and keep strict reverse-path filtering happy). A throw covers an endpoint's whole address, so any traffic to an entry's address goes around the tunnel; for an endpoint behind a CDN, whose address serves many sites, the throw should narrow to the transport's flow (protocol and port rules) when such transports come. Rules recompile into the table wherever the rules change (a map, the device's choice, a list arriving): direct prefixes the new rules drop leave the table before the router's table changes, new ones come after; a removal that fails falls back to nothing direct. All of it carries route protocol 86 (rules too, which needs Linux 4.17: on an older kernel the agent refuses rather than add rules it can't tell from others), so a restart after a crash takes it over, a stop removes it, and a device that starts without connecting removes what a crash left. After a crash both families stay unreachable but for direct destinations until the agent starts again.

GeoIP alone misroutes CDNs (foreign services on domestic IPs and vice versa), so the rule format supports domains from day one even though enforcement comes later.

**DNS is routing.** A resolver on the node's overlay address answers overlay names (`<device>.<space>.internal`; `.internal` is reserved for private use, so a space name can never shadow a real domain), sends `direct` domains to a domestic upstream, and everything else through the tunnel to a resolver at the exit. No DNS leaks, and GeoIP isn't fed CDN answers from the wrong country.

- **Names** are in devices' sections only (the space's name, the device's own and its peers'), so a device can name exactly the nodes it has as peers and a server holds no member names. The resolver serves the names of the peers WireGuard has now: a peer the map takes away leaves DNS with it. No name with an `internal` label anywhere (a search list's retry of an overlay name included) and no reverse name under the overlay is ever forwarded; names with escaped characters, which would be matched as other names than the ones asked, are refused.
- **Which way a name goes** is the device's effective rule list read by name (`rules.CompileNames`): `domain` matches exactly, `domain-suffix` the name and below, `default` everything; address matchers can't decide a name and are passed over; with the same fail-closed rules as the route table (an unknown matcher turns later `direct` rules off, a chain that can't carry traffic blocks, no match blocks, no rules at all is `direct`). A name's rule picks only the upstream; the answer's addresses are routed by the address rules like any other. A reverse name (PTR) goes where its address's packets go. A `direct` name whose answer is a CNAME into a tunnel-bound name is answered whole by the domestic upstream: the chain is resolved upstream, so its target's name was seen there (inherent in forwarding; the target's addresses are still routed by the rules).
- **Upstreams.** `direct` names go to the domestic upstream: what the OS used before the node took over, or `-dns-upstream`. Tunnel-bound names go to the resolver on the chain's exit's overlay address, which every exit (a server that allows egress) runs for the space's overlay, asking its own upstream (the host's non-loopback resolvers, or `-dns-upstream`); the overlay always routes into the TUN, and on Linux those sockets are bound to it, so such a query can leave through the tunnel or not at all. In route-table mode the direct upstream's sockets carry the links' socket mark, so they leave around the tunnel (TP-018). Answers are cached per route, bounded, and the cache is flushed on every map or rule change, so a direct upstream's answer is never served for a name that goes through the tunnel. Forwarded queries carry none of the client's EDNS options (subnet, cookies). A device's resolver answers the device itself only; an exit's, the space's overlay only.
- **The OS resolves through it** while a device is connected, and gets its own configuration back when it disconnects or stops. Linux: whenever systemd-resolved runs, the TUN becomes its link for every name (`~.`, over D-Bus); unless `/etc/resolv.conf` sends everything to resolved's stub, the file is rewritten too, atomically (in place only where it can't be renamed over: a bind mount), with the original kept inside it, so it comes back at the node's next start even after a crash or a reboot. The file is watched (inotify, polling as a backstop) and taken back if another program rewrites it; the resolvers it then names become the domestic upstream, as resolved's uplink servers do. While the node runs, the OS searches only the space's zone: a name that fails is never retried under the OS's own search domains, which the rules may send elsewhere, at the cost of short LAN names (`printer` for `printer.lan`) while connected. macOS is TP-019's.
- **Protection is checked, never assumed.** In systemd-resolved, a domain on another link (search or routing) beats the TUN's `~.` for the names under it, and another `~.` shares every name; NetworkManager adds `~.` to the connection with the default route. Any such domain, a failure to point the OS (retried on the agent's retry timer), or a rewrite that fails makes the device's health say `dns_not_protected`, and `thinkpol connect` returns an error saying so while the tunnel stays up.
- **Nothing is logged about a query**: no names or answers in any log or on disk; the resolver keeps counters only.

**Lists**: v2fly geoip/geosite or DB-IP Lite. The map references them by content hash: the header lists every blob the space uses, the set relays cache and pass on, and each section names only the blobs its node uses. A GeoIP blob is one list (a country) as its minimal set of IPv4 and IPv6 prefixes in a canonical encoding, so the same addresses always give the same hash, whatever the source or its order. Lists are built from files the operator downloads (DB-IP Lite, CC BY 4.0, by default); no third-party data lives in the repo and nodes never fetch from outside the network. Nodes fetch and cache them from peers (`dataplane/blobs`). Servers serve: a server's worker holds the header's whole set (from the seeds in its state directory, or fetched from other servers) and answers on its overlay addresses (TCP port 4717, inside WireGuard, sockets bound to the TUN), one request per connection by SHA-256, only to its WireGuard peers' overlay addresses, and only for blobs it holds, all of which a signed map of its space listed, so it is no oracle beyond the availability set. Devices only fetch: nothing on a device answers on the blob port. A node fetches what its map asks for from its WireGuard peers in map order, and uses a blob only once its size and SHA-256 match the map (and a GeoIP list decodes); a peer that sends anything else, or trickles below a minimum rate, is skipped for the next, and a new map abandons a transfer under way. A list in use is replaced only once its successor is verified, across a device's restarts too. Transfers are bounded (16 MiB a blob; a map's blobs together 16 MiB on a server, which the map builder keeps the header within, 64 MiB on a device; a few connections per peer; a shared serving rate) and resumable from an offset. The hashes of public lists are visible to every node holding the envelope, which only tells a node that the space uses, say, a Russian GeoIP list: an accepted leak.

### IPv6

The risk is leaking: if the local network has IPv6 and the tunnel doesn't carry it, apps connect around the tunnel, past the rules and in view of the censor.

- **Overlay:** dual-stack. IPv4 from `100.64.0.0/10`, plus a **random ULA /48 per space** (RFC 4193). Spaces are isolated in their own namespaces, so overlapping IPv4 ranges on a shared node are harmless. The overlay's MTU is what links leave after transport, path header and WireGuard, budgeted as IPv6 whatever a link's family (1328 for unshaped `udp` over 1500). It is meant to be space-wide, computed by the map builder from every link's budget (TP-030); until then each node uses the floor of its own links, and a relay drops and counts packets too long for its next link. Where the MTU is below IPv6's minimum of 1280, the overlay carries IPv4 only and the node's status says so.
- **Egress:** exits with IPv6 do NAT66; without it, IPv6 is blocked while connected. Never leaked either way.
- **Everything is dual-stack:** route-table rules (GeoIP lists carry IPv6 ranges), DNS (`AAAA`), and the kill switch.
- **Entries reachable over IPv6** are extra candidate paths. Censors sometimes treat IPv6 differently, which deserves a lab module.

### Direct paths (hole punching)

A later candidate path, not a separate feature. Nodes learn their public endpoint from our own server nodes (never public STUN), try direct UDP, and keep the relay as the fallback. Under a whitelist, traffic between two home or mobile IPs may simply not get through. Direct paths reveal each device's real IP to the other and show the censor encrypted UDP between home IPs, so they are a per-space setting.

### Desktop client

Two processes. The **service** is the node agent: it runs privileged (TUN, routes, firewall), installed as a launchd daemon, systemd unit or Windows service. The **tray app** is unprivileged and talks to the service over a local socket (named pipe on Windows) with a small gRPC API: connect/disconnect, status, space switcher, rule presets, kill switch, connect-on-boot. The CLI is a third client of the same API.

A device can be enrolled in several spaces but runs **one at a time**: switching spaces tears down one data plane and brings up the other.

**The local API** (`proto/thinkpol/localapi/v1`, served by `internal/agent/localapi`) is gRPC on a Unix socket, `/run/thinkpol-api/api.sock` on Linux (`/var/run/thinkpol-api/` on macOS; a named pipe on Windows, TP-047): status (connection, space and map version, health, peers with the entry each one's packets leave through, neighbors and links, egresses, IPv6 state, the last Apply's failed step, what the map held that the node skipped), a status stream, connect and disconnect, the enrolled spaces, rule presets, and the agent's in-memory log. Connect and disconnect bring a device's data plane up and down while the service keeps running and keeps following its space's maps; `thinkpol up -connect=false` starts disconnected. A server serves its spaces whenever it runs: it reports its workers and public listeners and refuses connect and disconnect. Who may do what:
- **The socket's directory is the first gate.** The service creates it `0750`, owned by root with the `thinkpol` group (`0700` if there is no such group), in a parent of root's that no one else can write to. A real directory of the service's user left from an earlier run gets the right group and mode through its own descriptor; a symlink or another user's directory is refused. Anyone outside the group gets "permission denied" when they connect. A lock file next to the socket keeps two services from taking it over at once; at most 32 connections and 16 calls per connection are served, and all status watchers share one snapshot per tick.
- **Every call checks the caller again** by the credentials the kernel recorded at connect time (`SO_PEERCRED` and `SO_PEERGROUPS` on Linux, `LOCAL_PEERCRED` on macOS): root and the service's own user may do everything; members of the group see the status and control the node (connect, disconnect, rule presets); the log is root's only, because its debug lines may quote the map. There is no read-only tier for other users: they can't reach the socket at all.
- **The API never takes the VPN down.** If it can't serve (a refused directory, a broken socket), the node logs it as an error and runs on without it, trying again every 10 seconds; only the status is unavailable meanwhile.
- **A rule preset chosen through the API** is stored by the service in the device's state directory (`rules.local`, next to the device's own rules), then handed to the engine (`Engine.SetRules`; `EngineConfig.Rules` at every start); nothing else writes it. It is read like the node's other files, and one that can't be read or parsed stops the node from starting rather than reading as "no rules". A preset the map can't build is kept and enforced failing closed, and the API says so.
- **Nothing the API reports is a public address, a key or a secret** (S1, S4): nodes and spaces are opaque ids, addresses are the overlay's, failures are named from fixed vocabularies (a failed connect names its step; the detail goes to the node's log), a server's listeners are shown without their addresses and its workers without their exit messages. Clients sanitize every string they receive before showing it (worker output and anything else from the service is never trusted with a terminal).

When the entry in use belongs to another space, the tray labels it **`owned by <space>`**: that space's node owner can see the member's IP and traffic volume (see Trust in the PRD).

**Kill switch:** while on and the tunnel is down, the firewall (pf, nftables, Windows Filtering Platform) allows only traffic to entry nodes, plus LAN when allow-LAN is set. A pause option covers captive portals.

### Node safety

What a censor finds on a seized or inspected server node:

| On the node | What it holds |
|---|---|
| Binary and systemd unit | — |
| Keys | One key set per space served; private keys generated on the node, never copied off |
| Map | Only the node's own decrypted part per space (see the signed map): ids, endpoints and credentials of the links it serves. **No member names, no rules it doesn't enforce, no other nodes' credentials.** Devices appear as opaque ids (a device's own section names its peers, for its overlay names) |
| Logs | None on disk. Agent logs go to an in-memory ring, readable over the overlay for debugging; provisioning sets journald to volatile storage |
| Telemetry | Only in memory, per space, bounded (on the order of 15 minutes and tens of kilobytes); **each record sealed to the space's telemetry key as it's written**, so neither a memory dump nor swap yields readable data; oldest dropped first; gone on reboot |

On disk that is the state directory (`/var/lib/thinkpol`), and nothing else: `node.key` (the node's id and private keys, 0600), written once, on the node, when it is provisioned; `space.pub` (the space's id and public keys, what every map is verified against); `map.bin`, replaced atomically whenever the node takes a newer map (TP-037); on a device that chose one, `rules.local` (its rule preset and own rules), written atomically by the service when the local API changes it; and `blobs/`, files named by their SHA-256. A server only reads `blobs/`: the seeds of its space's lists that provisioning put there, which the supervisor reads when it sends them to a worker (one sealed memfd each, kept nowhere else); what a worker fetches from peers stays in its memory, since a server uses no list itself and fetches the set again after a restart. A device keeps there the lists its rules use, with an index of their names, fetched from peers and pruned when the map stops naming them, because it needs them from the moment it starts, before any peer is reachable; the previous version of a list stays until its successor is verified. Either way the contents are public lists the map already names by hash, checked against the map whenever they are read. Directory and files belong to the node's user (or root), are writable by no one else and are never symlinks, and so is every directory on the way from `/` (a sticky one like `/tmp` may be passed through): whoever could replace `space.pub` would choose the maps the node trusts, and whoever could replace `map.bin` could put back an older signed map for the node's next start. `thinkpol up` writes nothing else there (a device's `blobs/` aside); a server's workers get their keys and map from the supervisor over their sockets, since they can't read it. Outside it, a connected device rewrites `/etc/resolv.conf` (unless the OS resolves through systemd-resolved): the overlay resolver's addresses and the space's zone, with the original kept inside the file and put back when the device disconnects or stops.

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

**The signed map.** One per space: a signed envelope with a header (space id, key epoch, version, the space's signing and recovery public keys, hashes of list files) and **one sealed section per node**, an anonymous sealed box to that node's map key (its own X25519 key, separate from its WireGuard key). Sections carry no recipient id: a node finds its own by trying to open each one, so nothing in the envelope links a section to a node, or a node's sections across versions. Each section holds only what its node needs:
- an entry gets the device ids it accepts, the transport's verifier for each one's credential (a hash or public key where the transport allows, the shared secret for a symmetric transport), per-link transport settings, and its forwarding table
- an exit gets the WireGuard keys and overlay addresses of devices allowed to use it
- a device gets rules, chains, reachable peers with their candidate first hops, and entry endpoints

Endpoints and listener addresses in the map are IP literals: the controller resolves names, so nodes never ask DNS at dial time, past the tunnel.

Versions only go up, and the envelope is signed by the space's **signing key**. Maps are ordered by **(key epoch, version)**; the epoch changes only through a recovery record (below), so a stolen signing key can't freeze the space by signing the highest possible version. Nodes accept a valid envelope with a higher version from anyone, including other nodes, so it spreads by gossip, but each can open only its own section. Rollback is impossible, and there is no expiry, so offline networks keep working. Revocation is a new version without the node.

**The section count is padded** to a fixed size (8, 16, 32, …) with dummy sections, so the envelope doesn't reveal how many nodes a space has. Every section of an envelope is padded to the same length (at least 8 KiB, a power of two) and the sections are shuffled, so neither length nor position tells a real section from a dummy, or a relay's section from a device's. 8 KiB holds every section of a space at the PRD's scale with room to spare; a much larger space moves to a bigger bucket, and that bucket is what remains visible.

**Format changes.** Every format keeps the format number and the header, with its layout, where format 1 has them, so any node can tell which space and version a newer envelope is even when it can't read the rest. New fields are added without a bump and ignored by older nodes. Fields older nodes must not ignore are rolled out per section first: each section names the lowest reader that understands it, and a node with an older reader doesn't use it. **The format number is bumped only after the release that reads the new format has rolled out through format-1 maps**, so no node is left unable to read its space's maps.

**Recovery key.** Created with the space and kept offline by the admin (printed phrase or QR code); never on the controller. The header carries its public key, and it can sign exactly one kind of record: "from key epoch N, the signing key is X". Nodes accept that record over the current signing key and move to the new epoch, so a lost or stolen controller is recovered by rotating to a new key instead of re-creating the space. Controller database backups are encrypted to the same key, so one thing kept offline restores everything.

**Shared nodes and maps.** The node owner's map tells the node which guest spaces it serves: each guest's space id, signing and recovery keys, cap, and the ingress and egress granted. The node then accepts the guest space's envelopes as well, but only for that guest's worker. Only the owner space's listeners are honored on a shared node; the supervisor reads each guest's inbound links from that guest's map to authenticate its connections. To the guest's controller, the shared node is an endpoint plus the grant, with nothing to provision.

**Joining.**
- Server: `thinkpol node add root@1.2.3.4` installs the binary and a systemd unit, hardens logging, enables forwarding, configures nftables, has the node **generate its own keys**, adds it to the map with ingress and egress off, and publishes; `thinkpol node set <node> --ingress --egress` opens it up. Every step is idempotent, so re-running is how you repair a node.
- Device: `thinkpol join <invite>`.
- Sharing: the node owner runs `thinkpol grant offer <node> --ingress --cap 50mbit`, and the guest admin runs `thinkpol grant accept <token>`.
- Updates: signed release binaries, distributed through the network like list files.

**Kernel usage.** `config`, `app`, `observability`, `sqlite` and `webui` for the controller; `grpckit` for the push channel to nodes, which needs **streaming RPCs** (missing in grpckit today: add server and client stream interceptors there first). The data plane uses plain ports and adapters with no DDD aggregates: packets aren't domain events.

The node agent uses go-kernel's `config` and `app` but not `observability` yet (it is stdout-only); that waits on KRN-005, which adds writer, level and format options.

**Protobuf contracts live in this repo** under `proto/`, buf-managed (the map format, the local service API, the controller's node API), never in go-kernel's `contracts/`. This is a deliberate thinkpol-only exception to the kernel convention of hosting consumers' contracts: these schemas are wire formats between thinkpol's own binaries, not contracts between separate services.

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
  dataplane/              # the engine that wires the subpackages below, nothing else
    tun/ router/ wg/ path/
    rules/                # routing rules: presets, the device's local file, compilation into prefixes
    transport/            # the transport port; adapters in transport/<name>/
    netcfg/               # interface addresses, MTU, routes, policy rules
    routetable/           # route-table rule enforcement on top of netcfg; the link sockets' mark
    nsthread/             # runs a function on an OS thread inside another namespace and moves the thread back
    firewall/             # kill switch (pf, nftables, WFP)
    egress/ dns/
    blobs/                # fetch-by-hash distribution of list files and releases between peers
    telemetry/
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
- **Engine and agent**: the data-plane engine (`dataplane.Engine`) is in-process wiring, configured by one call per map. Everything around it is the agent's: creating the TUN and its configurator, building the transport registry (with socket marking), watching for maps and applying each, and opening, serving and closing the listeners. `internal/agent` hands `thinkpol up` its adapters (the map watcher and the node), which the command runs with the local API's under go-kernel's `app.Run`: device mode runs one space's engine in-process on the node's own sockets; server mode runs the supervisor and a worker per space, each running the same data plane with the supervisor's shared listeners as its inbound. A node takes a new map when the file changes or on SIGHUP, through `(*Map).Next`. A valid newer map without a section for the node means it was removed from the space: the data plane (on a server, the space's worker and listeners) stops, the agent stays up and idle following the space's maps, and starts again when a later map includes the node. A node that finds itself removed when it starts (its map, valid, has no section for it) starts the same way, idle, rather than failing and being restarted over and over by its service manager.
- **Dependency direction**: `dataplane`, `netmap`, `lists` and `agent` never import `features` or `shared`; `dataplane`, `netmap` and `lists` never import `agent`; `dataplane`, `netmap` and `lists` don't import go-kernel; `features` never import `dataplane` or `agent`, nor each other (cross-feature calls go through `shared/ports`); `shared` never imports `features`. The planes meet only through the signed map.
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
| M0 | Two Linux nodes in the lab, hand-made map in the sealed-section format, `udp` transport, relay paths; server agent as supervisor + one worker in its own namespace | `ping` directly (device ↔ server) and device ↔ device via a relay, over IPv4 and IPv6 ([lab/M0.md](lab/M0.md)) |
| M1 | Exit node with NAT, route-table rules with GeoIP, DNS, IPv6 handling, macOS and Linux CLI clients | daily-usable on its own terms; leak tests pass |
| M2 | `tls` transport with probe fallback; lab v1 (blocklists, WireGuard fingerprint, entropy, prober) | `udp` fails the lab, `tls` passes |
| M3 | Chains and hop groups with failover; lab whitelist mode | `ru-entries → nl-exit` passes a whitelist; killing the active entry keeps an open connection alive |
| M4 | Controller on go-kernel: spaces, members, invites, SSH provisioning with hardening, map gossip, hosting grants and shared nodes, telemetry, admin panel with canvas | a fresh box joins with one command and shows up on the canvas; a second space shares the entry and the isolation and seizure checks pass |
| M5 | Desktop client: service + tray app on macOS, Linux, Windows; kill switch; connect-on-boot; invite links; space switcher | a non-technical member joins from an invite without a terminal |

After the MVP: Android, userspace enforcement (domain rules), direct paths, tuned traffic shaping, `ws` behind a CDN, ephemeral nodes.

## Out of scope (for now)

VPS provider APIs (every node is a fresh Linux box you rent yourself), automatic IP rotation (needs provider APIs), onion-layered encryption across hops, iOS, our own crypto. Android is the first step after the MVP, so data-plane packages must stay buildable for mobile (no cgo, no desktop-only dependencies outside `tun`, `egress` and the firewall adapters).

## Open questions

None right now; new ones go here.
