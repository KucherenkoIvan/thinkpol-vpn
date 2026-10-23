# thinkpol-vpn — Security design

The security part of the design: the threat model, the rules, the IPv6 leak guard, the kill switch and what a censor finds on a seized node. The entry point is [DESIGN.md](../../DESIGN.md); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

## Threat model

The censor this is built against, and the feature that answers each technique:

| Censor technique | Answer |
|---|---|
| **DPI** — protocol fingerprints (WireGuard, OpenVPN), SNI and IP blocklists | WireGuard is never on the wire; links between nodes use **transports** that look like ordinary traffic |
| **Active probing** — connecting to a suspected server to see what answers | Transports authenticate before revealing anything; unauthenticated connections are forwarded to a real site (camouflage target; not yet: RR30) |
| **Profiling** — traffic shape, packet sizes and timing, TLS-in-TLS patterns, TLS fingerprints (JA3/JA4) | Browser-grade TLS fingerprints (uTLS); padding, batching and timing in the transport (the shaping contract; tuned by the lab) |
| **Whitelists** — only approved destinations reachable | **Chains**: the first hop is a whitelisted (typically domestic) VPS, which relays to a foreign exit. Disguise alone can't pass a whitelist. Whitelisted addresses are scarce, so **one entry serves several spaces**. An allowlisted entry exists only where someone already controls an approved address (PRD Decisions, "Whitelist scope"): thinkpol uses one when it exists and doesn't promise a way past whitelist mode without one. Under whitelist mode only TCP passes, even to listed addresses |
| **Seizure or inspection of a node** — in-country entries sit in the censor's jurisdiction | **Nodes know only what they need**: their own part of the map, opaque ids, no logs on disk, telemetry only in memory and sealed (see [Node safety](#node-safety)) |
| **Seizure or compromise of a member device** — it sits in the censor's jurisdiction and keeps its key on disk | Not prevented; bounded. The device holds valid credentials, so an entry can't tell the censor from the member, and nothing in telemetry detects it. Its section shows its entries' endpoints, its chains, rules and peer ids, and it reaches whatever the member could. **Per-device grants (A3)** bound the damage: only the chains and devices it was granted. **Revocation** is a new map without the device and spreads by gossip as soon as one honest entry is reachable |
| **Apps on a member's device** — government-affiliated apps that probe whether blocked services answer and look for VPN state: interfaces, routes, DNS, reachability | Partly hidden, honestly. Can't be hidden: a TUN (`utun`) interface and its routes are visible to every local app, so is the resolver's configuration, and a blocked service that answers shows that something carries it; Android's VpnService is detectable by design. What helps: "all but domestic" keeps domestic apps' traffic on the domestic path (not the interface or the routes). Per-app split tunnelling in userspace mode is the later mitigation |

Not defended against: a censor that blocks everything foreign, a node owner abusing what an entry inherently sees (member IPs and traffic volume on its links) or running a modified binary (what the PRD says a node owner never sees holds for an owner running the honest one), and traffic analysis by a global observer ([RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md), [Not defended](../../RESIDUAL-RISKS.md#not-defended-see-threat-model)).

## Rules

1. **WireGuard is the inner layer only.** It provides end-to-end crypto, per-peer routing and rekeying; it never touches the network directly. Everything it emits goes through the path layer and a transport; on macOS a foreign host route to a peer's overlay address bypasses it (RR23).
2. **The controller is never a runtime dependency.** Configuration is a **signed network map**, not a live API. Nodes keep the last valid map indefinitely; with the controller switched off, the network keeps working and only stops changing.
3. **Chains are core, not an add-on.** A route to the internet is an ordered list of hops, chosen per destination by routing rules.
4. **No home-made crypto.** WireGuard (via wireguard-go), standard TLS, and NaCl-style sealed boxes. The project's own code decides *where* bytes go and *what they look like*, never how they are encrypted.
5. **Nodes know only what they need.** Every node can read only its own part of the map, and keeps nothing on disk it could do without.
6. **Spaces never touch.** On a shared node, each space gets its own network stack; nothing (packets, routes, DNS, telemetry) crosses between them.
7. **What a node can't resolve fails closed, with named exceptions.** A list not fetched, a matcher, action or shaping field it doesn't know, a preset the map can't build: none of them widens what goes direct or what a transport reveals; they block or refuse, and health says so. The exceptions are decisions, each a residual row: a section without rules, or with rules its node can't read, sends everything direct (RR28); an OS that can't host the IPv6 leak guard still connects (RR10, RR12); and until the node's own ceiling exists, the map alone decides a node's role (RR42).

## IPv6

The risk is leaking: if the local network has IPv6 and the tunnel doesn't carry it, apps connect around the tunnel, past the rules and in view of the censor.

- **Egress:** exits with IPv6 do NAT66; without it, IPv6 is blocked while connected. **Never leaked either way:** a device sends IPv6 into the TUN whenever the overlay carries it, and an exit without IPv6 refuses it there at once; with the overlay IPv4-only, the device's route table makes IPv6 unreachable; and either way the device's leak guard refuses IPv6 on the physical interfaces but to direct destinations, the entries and the direct DNS upstreams. The exceptions are the rows whose Breaks column names D6.
- **The leak guard** is a firewall owner of its own, applied with the routes and kept in place against other software (but RR11), and it stays when the agent dies, so IPv6 fails closed across a crash (but RR16). Its failure never fails the routes or a connect: it is reported and retried, and an OS that can't host it still connects, with a warning (RR10–RR12).
- **Everything is dual-stack:** route-table rules (GeoIP lists carry IPv6 ranges), DNS (`AAAA`), and the kill switch.

## Kill switch

While on and the tunnel is down, the firewall (pf, nftables, Windows Filtering Platform) allows only traffic to entry nodes, plus LAN when allow-LAN is set. A pause option covers captive portals. The IPv6 leak guard is the connection's, not the kill switch. Not built yet (RR17).

**After a crash the device fails closed by default** under the "everything" and "all but domestic" presets (opt-out): the firewall's rules stay in place when the agent dies without disconnecting, so an unattended crash or failed update leaks nothing, and they come out when the agent starts again and connects. A crash is the likeliest mass-exposure event, and the member least able to notice it is the one who never touched a setting (PRD Decisions, "Crash posture"). A **deliberate disconnect** is different and follows the kill-switch toggle (off by default, D4): the guard comes out, and the traffic goes direct unless the toggle is on. macOS must meet this too. Until the kill switch exists (TP-048), IPv4 flows after a crash (RR18).

**The service restarts a crashed agent, as the member left it.** Under the service (launchd's KeepAlive, systemd's Restart=always, no start limit) the agent comes back within seconds, and a device keeps its connect choice for the boot: a restart in the same boot neither drops a connected member nor undoes their disconnect, whatever connect-on-boot (off by default, D5) says; only a boot's first start follows connect-on-boot. A Connect that fails leaves the choice down.

## Node safety

What a censor finds on a seized or inspected server node:

| On the node | What it holds |
|---|---|
| Binary and systemd unit | — |
| Keys | One key set per space served; private keys generated on the node, never copied off |
| Map | Only the node's own decrypted part per space (see [the signed map](control-plane.md#the-signed-map)): ids, endpoints and credentials of the links it serves. **No member names, no rules it doesn't enforce, no other nodes' credentials.** Devices appear as opaque ids (a device's own section names its peers, for its overlay names) |
| Logs | None written by the agent: they go to an in-memory ring that only root reads, through the local API. Under systemd, stderr reaches the journal, which provisioning is to make volatile (RR40) |
| Telemetry | Only in memory, per space, bounded (on the order of 15 minutes and tens of kilobytes); **each record sealed to the space's telemetry key as it's written**, so neither a memory dump nor swap yields readable data; oldest dropped first; gone on reboot |

On disk a node keeps its state directory: its keys, the space's public keys, the space's map, a device's rule choice, and public lists named by hash. It, and every directory above it, can be changed only by root or the node's user: whoever could replace the space's keys would choose the maps the node trusts, and whoever could replace the map could roll the node back (RR46). Workers can't read it; the supervisor hands them what they need. Outside it a node keeps only what it must find again after a crash, recorded so the next start undoes or takes it over: its locks, under the service a device's connect choice for the boot, routes and leak guard, the OS's resolver configuration, on a server the supervisor's nftables tables and forwarding record, and on macOS route records, which name the entries' addresses, and a pf reference record (RR52).

Telemetry records are aggregates per link and per device id (rates, byte counts, path and transport in use, handshake failures), **never public IP addresses or destinations**. History lives only on the controller.

Later: **ephemeral nodes** keep nothing on disk but the binary. After a reboot they are blank, and the node owner's controller re-provisions them over SSH.

## Elsewhere

Security invariants that stay with their feature's design:

- [The route table](routing.md#route-table): only the rules decide what bypasses the tunnel, and what the TUN can't take is refused.
- [DNS](routing.md#dns): names go where their rule sends them, answers never cross routes.
- [The server agent](server-agent.md#server-agent-one-worker-per-space): a worker answers its peers, never anyone else; a replay must not be an oracle.
- [The signed map](control-plane.md#the-signed-map): sections carry no recipient id, and maps only move forward.
- [The local API](desktop-client.md#the-local-api): nothing it reports is a public address, a key or a secret, but root's half of `diag`, whose host parts name public addresses (never a key or a secret).