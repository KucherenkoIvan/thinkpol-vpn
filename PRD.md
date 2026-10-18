# thinkpol-vpn — Product Requirements

A self-hosted virtual network for people behind a censor: your devices and a few VPS nodes form one private network, traffic between them is disguised, and internet traffic can leave through a chain of hops. Managed like Tailscale (join with one command, manage from a panel), without depending on anyone's servers and without a protocol the censor can block on sight. How it works is in [DESIGN.md](DESIGN.md); this document is what it must do.

## Problem

- **Commercial VPNs and single-protocol tools get blocked.** WireGuard and OpenVPN are blocked by protocol fingerprint; servers get found by active probing and traffic profiling; under whitelists nothing foreign is reachable at all.
- **Whitelisted IPs are scarce.** The way past a whitelist is an entry node on a whitelisted address, and those are very hard to get and not for sale to regular citizens: since 2026 allowlisted services sit in subnets of their own, so renting a domestic VPS no longer lands one. Whoever has one has to be able to share it, or the people around them stay cut off.
- **Tools that do survive are a pain to run.** VLESS + Reality works, but it's a proxy configured by hand on every server and every client, with no network between your own devices and no fleet management.
- **Tailscale has the management experience right but fails under a censor:** WireGuard on the wire, clients depending on Tailscale's servers, and exits limited to a single hop.

## Users

| Role | Who | Needs |
|---|---|---|
| **Admin** | Runs one space: holds its signing key, rents its nodes, invites its members. The author runs a personal space; a family or friends' space has its own admin | Full control of the space's nodes, chains and rules; visibility into what gets blocked and where; changes without editing config files on servers |
| **Member** | Friends and family, invited once the network proves itself; not technical | Install, accept an invite, toggle on; never see a terminal |
| **Node owner** | An admin whose server node also serves other spaces, which is how scarce whitelisted entries get shared | Share a node without exposing their own space; cap and revoke what others use |

Scale is small on purpose: a handful of servers, up to ~20 devices per space, a few spaces sharing a node. **No large-scale distribution**, no public service, no billing.

## Goals

1. Reach the open internet from behind DPI, active probing and whitelists, with routing you control per destination.
2. One private network across all your devices: any device reaches any other, through a relay if needed.
3. A fresh Linux VPS becomes a working node with one command; the network is managed from a web panel, not config files.
4. Nothing in the data path depends on the controller or on third-party servers.
5. Share scarce entry nodes between spaces, with each space's traffic and routes fully isolated.
6. A seized or inspected node gives away as little as possible about the people using it.
7. Taste over convention: transports, routing policy and path selection are swappable parts, and the architecture is a testbed for go-kernel.

## Non-goals

- Large-scale or public distribution, accounts for strangers, payments.
- VPS provider integrations (creating servers through APIs) and automatic IP rotation.
- Anonymity against a global observer; onion encryption across hops.
- Mobile clients in the MVP (Android comes right after; iOS isn't planned).
- Our own cryptography.

## Concepts

| Term | Meaning |
|---|---|
| **Space** | An isolated network ("tailnet", "organization") with its own admin, members, nodes, rules, address ranges and signing key. A device is active in one space at a time; a server node can serve several. |
| **Node** | Anything running the agent. **Server** nodes are Linux VPS; **devices** are member desktops (later phones). Every server node relays; two settings decide what else it may do: **allow ingress** (devices may connect to it, so it can start a chain) and **allow egress** (internet traffic may leave from it, so it can end a chain). With both off, the node accepts only traffic from other server nodes and only relays. |
| **Hosting grant** | A node owner's permission for another space (the guest space) to use one of its server nodes: a bandwidth cap and which of the node's ingress and egress the guest may use; revocable. |
| **Hop group** | A set of server nodes plus a selection policy (`failover`, `lowest-latency`, `spread`). |
| **Chain** | An ordered list of hops (nodes or hop groups), e.g. `ru-entries → nl-exit`. The first hop must allow ingress and the last must allow egress. A node's part in a chain comes from its position, not from the node: the same VPS can start one chain, sit in the middle of another and end a third. |
| **Transport** | How one link between two nodes looks on the wire (`udp`, `tls`, `ws`, …). Chosen per link. |
| **Rule** | `match → action`: `geoip:ru → direct`, `domain-suffix:example.com → chain:nl`, `default → chain:ru-nl`. |
| **Network map** | The space's full configuration, signed by its admin key. Each node can read only the part it needs. The network runs on the last valid map. |

## User stories

**Getting started**
- As an admin, I create a space and turn a fresh Linux box into a node with one command, without hand-editing anything on the server, then choose whether devices may connect to it, internet traffic may leave from it, both, or neither.
- As an admin, I invite a member with a link or QR code; they install the client and open the invite, and once I approve their device they are connected, without a terminal.
- As an admin, I see devices waiting for approval and approve or reject them; one I don't approve in time expires.
- As a member, I'm enrolled in several spaces (mine and my family's) and switch between them from the tray; one is active at a time.

**Everyday use**
- As a member, I click the tray icon to connect or disconnect, and see whether I'm connected, through which chain, and whether something is wrong.
- As a member, I choose what goes through the tunnel: everything, everything except domestic sites (the default), or my own rules on top of the space's defaults.
- As a member, I turn on the kill switch so nothing leaks when the tunnel drops, and still log into hotel Wi-Fi (allow-LAN, temporary pause).
- As a member on "everything" or "all but domestic", I'm not exposed when the agent crashes: nothing leaks until it is back, without my having changed a setting.
- As a member, I turn on connect-on-boot (off by default).
- As a member, I reach my other devices (SSH to my desktop, a file share) by name, wherever they are.

**When the censor moves**
- As a member, when my entry node gets blocked, the client switches to another one by itself, without breaking open connections.
- As an admin, I see in the panel which transports and entries are failing and from where, and change a chain's transport or add an entry; clients pick the change up without anyone touching their devices.

**Sharing a node**
- As a node owner, I let another space use my whitelisted entry. Its traffic, routes and addresses are isolated from my space's, and I cap its bandwidth.
- As a node owner, I revoke a grant and the other space loses the node at once, without anything changing for my own space.
- As the admin of a guest space, I use the shared entry in my chains and see its health for my traffic, but can't change or inspect the node itself.

**Managing the fleet**
- As an admin, I see the network as a canvas, like Packet Tracer: nodes, links, transports, chains drawn as paths, live health and traffic on top. I edit topology there: drag a link, assign a transport, build a chain.
- As an admin, I decide per node whether devices may connect to it (ingress) and whether internet traffic may leave from it (egress). A node with neither stays hidden from devices and only relays.
- As an admin, I see node health, connected devices, traffic rates, transports in use and active routes.
- As an admin, I remove a member or a lost device, and it loses access everywhere at the next map update.
- As an admin, I can switch the controller off; the network keeps working, it just stops changing.

**Safety**
- As a member, if the censor seizes or inspects an in-country entry node, it finds as little as possible about me: no names, no logs, no history of my traffic.

## Functional requirements

Milestones as in [Release plan](#release-plan). Priority: **must** for the MVP, **should** if time allows, **later** post-MVP.

### Network

| ID | Requirement | Pri | M |
|---|---|---|---|
| N1 | Every node in a space gets an overlay IPv4 address and a per-space random IPv6 (ULA) address | must | M0 |
| N2 | Any device reaches any other device in its space, through a relay when no direct path exists | must | M0 |
| N3 | Overlay names resolve: `<device>.<space>.internal` | must | M1 |
| N4 | Direct device-to-device paths via hole punching, relay as fallback; a space-level setting | later | — |
| N5 | A server node serves several spaces; each gets its own isolated network stack on the node (addresses, routes, firewall, NAT, keys); no traffic or route crosses spaces | must | M4; the agent is structured for it from M0 |
| N6 | Spaces sharing a node share its public address and port; the transport's authentication decides which space a connection belongs to | must | M4 |
| N7 | Bandwidth cap per guest space, set by the node owner; fair share between spaces under load | must | M4 |
| N8 | Per-node **allow ingress** and **allow egress** settings, both off by default and changeable without reinstalling. With ingress off, the node accepts only other server nodes and its address is never given to devices; with both off, it only relays | must | M1 |
| N9 | Chains are valid only if the first hop allows ingress and the last allows egress (for a guest space: as granted); for a hop group, every member | must | M3 |

### Egress and routing

| ID | Requirement | Pri | M |
|---|---|---|---|
| R1 | Nodes that allow egress forward internet traffic for the space (IPv4; IPv6 if the VPS has it) | must | M1 |
| R2 | Ordered rules with actions `direct`, `chain:<name>`, `block`; matchers `default`, `cidr`, `geoip` | must | M1 |
| R3 | Space-wide default rules plus per-device overrides; presets "everything" and "all but domestic" | must | M1 (presets per device); M4 (per-device custom rules, set by the controller) |
| R4 | DNS follows the rules: `direct` domains go to a domestic resolver, everything else through the tunnel; no DNS leaks | must | M1 (Linux lab; macOS: TP-019 device run 4, from its hand-read capture) |
| R5 | Chains of two or more hops; hops can be hop groups | must | M3 |
| R6 | Hop group policies `failover`, `lowest-latency`, `spread` | must: failover; should: others | M3 |
| R7 | Switching entries keeps the exit, so open connections survive | must | M3 |
| R8 | Domain matchers (`domain`, `domain-suffix`, `geosite`) enforced in userspace mode | later | — |
| R9 | GeoIP/geosite lists distributed through the network and updatable without a release | must | M1 (GeoIP); geosite: later, once it has a format |

### Censorship resistance

| ID | Requirement | Pri | M |
|---|---|---|---|
| C1 | No WireGuard (or other known VPN) fingerprint on any link | must | M0 |
| C2 | `reality` transport: browser-grade TLS fingerprint (REALITY's handshake); unauthenticated connections forwarded to a real site | must | M2 |
| C3 | Transport chosen per link, changeable from the panel without reinstalling anything | must | M2 |
| C4 | Censor lab: Compose environment with switchable censor modules (IP/SNI blocklists, VPN fingerprints, fully-encrypted heuristics, active prober, JA3/JA4, whitelist mode, throttling) and a generated pass/fail matrix | must | M2–M3 |
| C5 | `ws` transport usable behind a CDN | should | — |
| C6 | Each transport owns traffic shape: padding, batching and timing that hide inner packet sizes and rhythm, configurable per transport; the lab measures what's enough | must: the contract; later: tuned shaping | M2 |

### Node safety

| ID | Requirement | Pri | M |
|---|---|---|---|
| S1 | Nodes keep only what they need to run: their own keys and their own part of the map. No member names, no other nodes' credentials, no rules they don't enforce; servers know devices by opaque ids | must | M0 for the map format, M4 complete |
| S2 | No logs on disk: agent logs stay in memory; provisioning makes the system journal volatile | must | M4 |
| S3 | Telemetry is buffered on nodes only in memory, bounded (minutes, kilobytes), encrypted to the space's key as it's recorded; oldest dropped first when full, everything lost on reboot | must | M4 |
| S4 | Telemetry holds aggregates per link and per device id; never public IP addresses or destinations | must | M4 |
| S5 | Ephemeral nodes: nothing on disk but the binary; after a reboot, the node owner's controller re-provisions them | later | — |
| S6 | The map doesn't reveal how many nodes a space has (padded to fixed sizes) | must | M4 |

### Client (desktop)

| ID | Requirement | Pri | M |
|---|---|---|---|
| D1 | Runs on macOS, Linux, Windows | must | M1 (macOS, Linux), M5 (Windows) |
| D2 | Privileged background service + unprivileged tray app; the tray app talks to the service locally | must | M5 |
| D3 | Tray: connect/disconnect, status (chain, entry in use, health), space switcher, rule preset switcher | must | M5 |
| D4 | Kill switch toggle (default off): when on and the tunnel is down, nothing leaves except traffic to entry nodes; allow-LAN option; temporary pause. After an agent crash the device **fails closed by default** under the "everything" and "all but domestic" presets (opt-out); a deliberate disconnect follows the toggle | must | M2 (macOS, Linux), M5 (Windows) |
| D5 | Connect-on-boot toggle (default off) | must | M2 (macOS, Linux), M5 (tray toggle, Windows) |
| D6 | No IPv6 leaks: IPv6 goes through the tunnel or is blocked while connected | must | M1 (Linux); macOS device proof once a network with native IPv6 is available (TP-096) |
| D7 | Join a space from an invite link or QR code without a terminal; the device stays pending until the admin approves it | must | M5 |
| D8 | CLI covering everything the tray does | must | M1 |
| D9 | Enrolled in several spaces, one active at a time | must | M5 |
| D10 | When the entry in use belongs to another space, the tray shows `owned by <space>` | must | M5 |

### Control plane and admin panel

| ID | Requirement | Pri | M |
|---|---|---|---|
| A1 | Each space is managed by its own admin, who alone holds its signing key; a controller manages one admin's spaces | must | M4 |
| A2 | Members with roles (admin, member); invites expire and are single-use; redeeming one creates a pending device with no access until the admin approves it, and pending devices expire | must | M4 |
| A3 | Access grants: which chains a member may use, whether a device is reachable by the whole space or only its owner | must | M4 |
| A4 | `node add root@host` over SSH: idempotent install, keys generated on the node, re-run repairs; the node starts with ingress and egress off | must | M4 |
| A5 | Network map signed per space, distributed by gossip; nodes keep the last valid map; removal takes effect at the next map | must | M4 |
| A6 | Web admin panel, reachable only through the overlay | must | M4 |
| A7 | Canvas view: nodes, links, transports, chains; live state on top; editing topology on the canvas | must: view + live state; should: editing | M4 |
| A8 | Dashboards: node health, connected devices, traffic rates, transports in use, active routes, failures per transport and entry | must | M4 |
| A9 | Signed agent updates distributed through the network | should | M4 |
| A10 | Hosting grants: a node owner offers a node to another space with a bandwidth cap and the ingress/egress the guest may use, that space's admin accepts, the node owner can revoke. Guest admins see their own slice's health only; node-level control (updates, grants) stays with the node owner | must | M4 |
| A11 | Offline recovery key per space: rotates a lost or stolen signing key without re-creating the space, and decrypts controller backups | must | M4 |

## Non-functional requirements

| Area | Requirement |
|---|---|
| **Independence** | With the controller off, existing nodes and devices keep working indefinitely on the last map. No third-party servers anywhere in the data path (no public STUN, no vendor relays). |
| **Performance** | Through a two-hop chain on 1 vCPU VPS nodes: video calls without noticeable degradation, 1080p streaming, ≥ 50 Mbit/s throughput. Overhead beyond network RTT ≤ 10 ms per hop. Targets to validate in the lab. |
| **Failover** | A blocked or dead entry is detected and replaced within 15 s; no flapping (hysteresis). |
| **Isolation** | On a shared node, no packet, route, DNS answer or telemetry record of one space is visible to another. One space's load can't starve another past its fair share. |
| **Privacy** | Nodes never log destinations. Telemetry history lives only on the controller (24 h by default), which runs outside the censor's reach; nodes hold minutes of it, sealed, in memory (S1–S4). Private keys never leave the node that generated them. |
| **Trust** | A node owner sees a guest space's traffic volume and its members' IP addresses on the link (unavoidable for an entry), never the traffic contents, rules or member list. This holds for an owner running the honest binary; one who modifies it can read what their node handles. |
| **Security** | Map changes require the space's admin key; nodes reject older map versions. A removed device loses access at the next map. |
| **IPv6** | Dual-stack inside the overlay; rules, DNS and the kill switch cover both families. |
| **Scale** | Designed for ≤ 10 servers, ≤ 20 devices per space, a few spaces per shared node. Nothing must be designed for more. |
| **Operability** | Joining, repairing and updating a node are single idempotent commands. |
| **Openness** | The core repo is public; transports can live in private plugin packages. |

## Release plan

| | Milestone | Ships |
|---|---|---|
| M0 | Overlay | Two Linux nodes in the lab, hand-made signed map in the need-to-know format, `udp` transport, relay paths, device ↔ device ping. The server agent already runs each space as its own isolated worker |
| M1 | Working core | Per-node ingress/egress settings, an egress node, rules with GeoIP, DNS, IPv6 handling, macOS and Linux clients via CLI. Leak guarantees are proven on Linux. On macOS, M1 proves the data plane, DNS and that the IPv6 guard loads on a real Mac; the guard's leak paths on native IPv6 are proven once a network with native IPv6 is available (TP-096); confinement after a crash (kill switch, TP-048) comes in M2. Daily use starts once a disguised transport passes the censor lab (M2) |
| M2 | Disguise | `reality` transport with probe fallback, censor lab v1; kill switch and connect-on-boot on macOS/Linux (TP-048, TP-046) |
| M3 | Chains | Multi-hop chains, hop groups with failover, lab whitelist mode (chains through an allowlisted entry; obtaining one is not promised) |
| M4 | Control plane | Controller on go-kernel: spaces, members, invites, SSH provisioning, map gossip, hosting grants and shared nodes, node safety, telemetry, admin panel with canvas and dashboards |
| M5 | Desktop client | Tray app on macOS, Linux, Windows; invite links; space switcher (kill-switch and connect-on-boot toggles in the tray; Windows enforcement) |
| — | **MVP = M0–M5** | |
| next | Android | Client on Android (data plane already buildable for mobile) |
| later | | Domain rules in userspace mode, direct paths, traffic shaping, `ws` behind a CDN, ephemeral nodes |

## Success metrics

1. **Lab:** every MVP transport has a known result against every censor module; `reality` passes everything except whitelist mode, and chains pass whitelist mode through an allowlisted entry.
2. **Daily use:** once a disguised transport passes the censor lab (M2), the author replaces VLESS + Reality on macOS for a month without falling back.
3. **Hand-off:** one family member or friend installs, joins and uses it without help.
4. **Sharing:** a second space runs through the author's entry node, and the lab confirms nothing crosses between the two.

## Risks

| Risk | Mitigation |
|---|---|
| The censor seizes or inspects an in-country entry node | Need-to-know map parts, opaque ids, no disk logs, sealed in-memory telemetry (S1–S4); ephemeral nodes later |
| The censor seizes or compromises a member's device | It holds valid credentials, so it passes as the member until revoked. Per-device grants (A3) bound what it reaches; revocation spreads by gossip once one honest entry is reachable; the section shows only that device's entries, chains and rules |
| Government-affiliated apps on members' devices probe for blocked services and for VPN state | A TUN interface, its routes and the DNS configuration are visible to local apps and can't be hidden; Android's VpnService is detectable. "All but domestic" keeps domestic apps' traffic on the domestic path; per-app split tunnelling in userspace mode is the later mitigation; researched in TP-065 |
| The censor learns our transports (the repo is public) | Probe resistance and fingerprint mimicry don't rely on secrecy; private plugins for experiments; transports swappable per link without releases |
| Whitelists tighten to the point where even domestic VPS IPs are filtered | This happened in 2026: allowlisted services were moved into subnets of their own, and a rented VPS address rarely passes. An allowlisted entry, where a node owner has one, is shared between spaces; hop groups and failover; otherwise members on a filtered mobile network use fixed broadband or wait for the regional switch to turn off; CDN-fronted `ws` only while an allowlisted CDN still carries it |
| Running an entry inside Russia exposes its owner | Since 2025 KoAP article 13.52 fines the owner of hardware or software that gives access to blocked resources, private persons included; since 26 June 2026 a hosting provider must stop serving such an owner (law 210-FZ), and users report virtual machines closed on suspicion of VPN use. An in-country entry is a legal risk to whoever runs it, not only a seizure risk: the docs say so before anyone sets one up, and such entries are treated as disposable (ephemeral nodes later) |
| A shared node is lost or its node owner stops cooperating | Guest spaces keep alternative entries in their hop groups; revocation is clean on both sides |
| Scope: this is several products in one | Milestones each deliver something usable; the lab defines "done"; the MVP excludes mobile and direct paths |
| Windows (Wintun, routing, service install) eats time | Last in the MVP; nothing earlier depends on it |
| The canvas editor clashes with go-kernel's server-rendered `webui` | Canvas as a JS island inside htmx pages; record it as a kernel lesson (provisional; the frontend stack is revisited in TP-086) |

## Decisions

- **Naming.** Product: thinkpol-vpn. Binary: `thinkpol`, split into `thinkpol-<role>` only if a real need appears.
- **Controller placement.** Default: a server node the admin owns outside the censor's jurisdiction, reachable only through the overlay. A laptop works, but dashboards then only fill while it's on.
- **Signing key recovery.** An offline recovery key (A11), not re-creating the space or keeping several signing keys.
- **Traffic shape.** Delegated to transports (C6); there's no better layer for it.
- **Reality.** The owner wants REALITY support: the `reality`-style transport is pulled forward as a VLESS/Reality-compatible transport, so existing VLESS/Reality servers and tooling can interoperate; researched first (TP-064). A "bridge" node type (a VLESS ingress routed into the overlay) was considered and set aside as too complex for now.
- **REALITY is the M2 disguised transport (2026-10-15).** After the TP-064 findings, thinkpol implements REALITY's handshake (a uTLS browser ClientHello with the session-id seal; failed auth is spliced to a real target site) for client → entry links (TP-087). Our own `tls` transport (TP-028) moves to after the MVP: adding REALITY doesn't block a TLS/TCP transport later, and it saves time to the MVP. Reuse over rewrite where licences allow: uTLS (BSD-3) is imported; XTLS/REALITY and Xray-core (MPL-2.0) may be used as unmodified Go module dependencies, but their files are never copied into this tree under MIT; TP-087 decides between depending on XTLS/REALITY's server and reimplementing it. Stock VLESS clients and servers are not supported by this transport: thinkpol is a WireGuard mesh, VLESS is a proxy protocol.
- **Whitelist scope (2026-10-16).** Chains pass whitelist mode through an allowlisted entry where a node owner has one; thinkpol doesn't promise to obtain one. Public research in October 2026 found the shared-subnet route closed (allowlisted services moved into subnets of their own, January and August 2026), and only legal entities can apply for the list. Under whitelist mode only TCP passes, so an entry under it needs a TCP transport (`reality`).
- **Agent modelling (2026-10-18).** The agent's connection lifecycle is an entity with typed states, transitions and events; invariants live in its methods. One state file does not warrant repositories or a transaction manager.
- **The node's own configuration caps the map (2026-10-18).** A node does only what it was allowed to on the machine itself: a fresh install is a device, and running as a server, ingress, egress and relaying are opted into locally, the way Tailscale exit nodes are advertised before an admin can use them. The space's signed map acts within that and never widens it. A map that asks for more leaves a starting node down and a running node on its last accepted capabilities, reported loudly; peers, keys and revocations are always taken. Why: a member's machine is theirs, and a stolen signing key or a compromised controller must not turn the space's nodes into exits. Devices as exits and as routers into a home network are set aside until after the MVP (DESIGN, Out of scope).
- **Crash posture.** Fail-closed after an agent crash is the default for the "everything" and "all but domestic" presets, opt-out (D4): a crash is the likeliest mass-exposure event and the members affected can least act on it.
- **Invites are not membership.** A redeemed invite creates a pending device the admin must approve (A2), because invites travel through surveilled channels.
- **What a node owner sees.** A shared entry sees guest members' IPs and traffic volume; under a whitelist it must be their first hop, so nothing can hide that. Accepted between friends and family, and disclosed: the tray labels such entries `owned by <space>` (D10).

## Open questions

- **Admin panel: organisation, authentication and authorization (A6).** On hold: the owner hasn't decided how the panel is organised. To be designed before TP-042 starts; the overlay is not access control (see DESIGN.md "Open questions").
