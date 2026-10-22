# thinkpol-vpn — Control plane design

The control plane: the controller on go-kernel, the signed map, joining, and the kernel usage. The entry point is [DESIGN.md](../../DESIGN.md).

### Control plane (the controller, on go-kernel)

Until a space has its controller (or instead of one, by choice), it runs hand-operated: [docs/runbook-pre-controller.md](../runbook-pre-controller.md) is the operating model of that period — maps built with the dev tooling (`dev map build`, `dev map rotate`), copied to servers over SSH and to devices by hand, restarts after reboots, binary updates, and chrony for the clock agreement the transports rely on.

A DDD service: CLI plus `thinkpol admin serve` for the web panel, reachable **only through the overlay**. That is a network control, not access control: members' devices are on the overlay by design, and the controller holds the space's signing key. How the panel is organised, authenticated and authorised is open (see Open questions); its canvas is planned in [`shared`](../../internal/shared/doc.go).

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
