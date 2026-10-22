# thinkpol-vpn — Routing design

Routing: the rule list, the route table, DNS and the lists. The entry point is [DESIGN.md](../../DESIGN.md); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

## Routing rules and DNS

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

## Route table

What route-table mode guarantees on every OS:

- **Only the rules decide what bypasses the tunnel**: the direct destinations and the links' own endpoints. No route another party adds (DHCP classless routes, TunnelVision; a public subnet declared on-link, LocalNet; another VPN's) takes tunnelled traffic around the tunnel. A local network is trusted only where it lies inside the local ranges *and* the rules send it direct; hosts on a public on-link LAN go through the tunnel. macOS, which has no policy routing, can only shadow foreign routes, after a debounce, and never a host route (RR22, RR23).
- **The links bypass the tunnel by their sockets**, and their endpoints are routed around it too, so a link never loops into its own tunnel, and nothing names the gateway where the OS lets us avoid it: roaming needs no change.
- **What the TUN can't take is refused**, not sent around the tunnel: IPv6 when the overlay doesn't carry it, and the overlay's own networks always. While the TUN is down IPv6 stays refused, but IPv4 follows the physical default route for a debounce first (RR19), and after a crash until the next start (RR18).
- **Direct shrinks before the router changes and grows after**, so a rule change never sends a tunnelled destination direct; a failed shrink falls back to nothing direct; if that fails too, the old set stays (RR14).
- **Everything installed is ours by mark and record**, so a restart after a crash takes it over, a stop removes it, and nothing of other software is touched.
- **Sockets the routing table can't hold** (bound to an interface, or routed by their source address) are the firewall's: the IPv6 leak guard confines them now; IPv4's wait for the kill switch (RR21).
- **The table is kept in place**: re-applied on every change of links, addresses or routes and periodically; health says when it isn't enforced.

## DNS

**DNS is routing.** A resolver on the node's overlay address answers overlay names (`<device>.<space>.internal`; `.internal` is reserved for private use, so a space name can never shadow a real domain), sends `direct` names to a domestic upstream, and everything else through the tunnel to a resolver at the exit. So GeoIP isn't fed CDN answers from the wrong country, and names don't leak, but for the rows whose Breaks column names R4.

- **A name goes where its rule sends it**: the device's effective rule list read by name, with the same fail-closed rules as the route table. A name's rule picks only the upstream; the answer's addresses are routed by the address rules like any other. A tunnel-bound query leaves through the tunnel or not at all. A `direct` name aliased into a tunnel-bound one tells the domestic upstream its target (RR1).
- **Names stay inside the space.** Overlay names are in devices' sections only, so a server holds no member names, and a device names exactly the peers it has now. Nothing under `.internal` and no reverse name of the overlay is ever forwarded; forwarded queries carry none of the client's EDNS options.
- **Answers never cross routes**: they are cached per route and the cache is flushed on every map or rule change, so a direct upstream's answer is never served for a name that goes through the tunnel.
- **Upstreams.** An exit asks public resolvers, not the host's: on most clouds the host's sit on private or link-local addresses, which the worker's egress refuses, and widening it would open the provider's network, metadata services included, to every space. An upstream the egress refuses is reported, never silently dropped.
- **The OS resolves through the node while it is connected**, and gets its own configuration back when the device disconnects, stops or restarts after a crash. Where the OS can't be made to, it is never assumed: health and `thinkpol connect` say so while the tunnel stays up (RR2).
- **Nothing is logged about a query**: no names or answers in any log or on disk; the resolver keeps counters only.

## Lists

GeoIP lists are blobs the map references by content hash: one list per blob in a canonical encoding, so the same addresses always give the same hash. They are built from files the operator downloads (no third-party data lives in the repo) and travel between peers inside WireGuard: nodes never fetch from outside the network. A node uses a blob only once it matches the map, and replaces a list in use only once its successor is verified. Servers serve only blobs a signed map of their space listed, so they are no oracle beyond that set; the hashes themselves are visible to every holder of the envelope (RR45).
