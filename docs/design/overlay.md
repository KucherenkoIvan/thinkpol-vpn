# thinkpol-vpn — Overlay design

The overlay: the data plane's layers, IPv6 addressing, destination routing, direct paths, and the node agent around the engine. The entry point is [DESIGN.md](../../DESIGN.md); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

## Data plane (every node, one binary)

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

## IPv6 addressing

- **Overlay:** dual-stack. IPv4 from `100.64.0.0/10`, plus a **random ULA /48 per space** (RFC 4193). Spaces have namespaces of their own, so overlapping IPv4 ranges on a shared node are harmless. Where the overlay's MTU is below IPv6's minimum of 1280, the overlay carries IPv4 only and the status says so.
- **Entries reachable over IPv6** are extra candidate paths. Censors sometimes treat IPv6 differently, which deserves a lab module.

## Direct paths (hole punching)

A later candidate path, not a separate feature. Nodes learn their public endpoint from our own server nodes (never public STUN), try direct UDP, and keep the relay as the fallback. Under a whitelist, traffic between two home or mobile IPs may simply not get through. Direct paths reveal each device's real IP to the other and show the censor encrypted UDP between home IPs, so they are a per-space setting.

## Node agent

The data-plane engine is in-process wiring, configured by one call per map. It owns the ports it drives and imports no host adapter; everything around it is the agent's: following the space's maps, building the transports, running the listeners, and sequencing the host's adapters, which the composition root picks per OS.

- **One node agent per host.** Before anything of the node touches the host, the agent takes the host's agent lock, because a second agent's start-time cleanups would undo the running agent's routes and resolver configuration.
- **A removed node idles, it doesn't fail.** A valid newer map without a section for the node stops its data plane; the agent stays up following the space's maps and starts again when a later map includes it, and a node that finds itself removed at start starts idle the same way, rather than being restarted over and over by its service manager.
- **A device's connection is one state with its transitions** (PRD Decisions, "Agent modelling"): a move its state can't make is refused and logged as a bug. What happens to a node is told as typed events, once per edge, not on every retry that fails again.
- **The node's own configuration is a ceiling over the map** (planned, TP-111; until then RR42; PRD Decisions). What a machine may do is allowed on the machine, by whoever runs it: `device`, or `server` with ingress, egress and relaying each opted into locally, the way a Tailscale device advertises itself as an exit node before an admin can use it. The space's signed map acts within the ceiling and can never widen it: peers, keys and revocations are always taken from a newer map, a role beyond the ceiling never is, and the node says so. Nodes need no agreement among themselves: to the space, a node that refuses a role is like one that is down, which hop groups route around. Each node enforces it even once the controller checks it: a controller can be compromised.