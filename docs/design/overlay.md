# thinkpol-vpn — Overlay design

The overlay: the data plane's layers, destination routing and direct paths. The entry point is [DESIGN.md](../../DESIGN.md).

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


### Direct paths (hole punching)

A later candidate path, not a separate feature. Nodes learn their public endpoint from our own server nodes (never public STUN), try direct UDP, and keep the relay as the fallback. Under a whitelist, traffic between two home or mobile IPs may simply not get through. Direct paths reveal each device's real IP to the other and show the censor encrypted UDP between home IPs, so they are a per-space setting.
