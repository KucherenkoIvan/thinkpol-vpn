---
id: TP-020
title: "DNS resolver"
milestone: M1
area: dataplane/dns
repo: thinkpol-vpn
size: L
depends_on: [TP-011, TP-015]
refs: [N3, R4, DESIGN#routing-rules-and-dns]
owner: "agent-tp-020"
branch: "tp-020-dns-resolver"
---

## Goal
DNS follows the routing rules: overlay names resolve, `direct` domains use a domestic resolver, everything else resolves through the tunnel, and nothing leaks.

## Scope
- Resolver on the node's overlay address (e.g. `miekg/dns`): answers `<device>.<space>.internal` (A and AAAA) from the map.
- Forwarding: domains with a `direct` rule to the domestic upstream; everything else through the tunnel to a resolver at the egress node.
- OS integration with restore on shutdown: Linux (systemd-resolved over D-Bus, `resolv.conf` fallback), macOS (`scutil` / `/etc/resolver`).

## Acceptance
- [x] lab capture: no DNS query leaves the device outside the tunnel except to the domestic upstream for `direct` domains — `lab/dns_test.go` `TestDNSFollowsTheRules`: a capture on each device's physical side (device-a through `/etc/resolv.conf`, device-b through systemd-resolved) shows port 53/5353 only to and from the domestic resolver, with direct names only, and no tunnel-bound, blocked or overlay name in the clear in any packet; the exit's upstream logs the tunnel-bound names asked by the exit's address, the domestic resolver never sees them
- [x] overlay names resolve on Linux — the same test: `<node>.lab.internal` (A and AAAA) through glibc via resolv.conf and via systemd-resolved; a name the map doesn't have is NXDOMAIN, and `.internal` is never forwarded. macOS (`scutil` / `/etc/resolver`) moved to TP-019 (`needs_human: macos`), see Notes

## Notes
**Built (TP-020):**
- **Names in the map** (`internal/netmap`, schema fields `Section.space_name` 14, `NodeSettings.name` 10, `Peer.name` 5; section reader stays 1, older readers ignore them): only devices' sections hold names, so a device can name exactly the nodes it has as peers and servers hold no member names. `netmap.CheckLabel` (one DNS label, no dash at either end); Build refuses names in a server's section, names without a space name, invalid labels, two nodes with one name. Readers don't check: the resolver ignores names it can't serve.
- **Dev spec** (`internal/devmap`): `space.name`, `rules` (text form) and `chains` (`{name, exit}`, the exit a server with `egress: true`); every device's section gets the names (when the space has one), the rules and the chains, so every device needs a path to each chain's exit and the list of each `geoip` rule in its `lists` (geosite refused until there is a format). `lab/maps/dns.yaml` uses them.
- **Rules by name** (`rules.CompileNames` → `*rules.Names`, `Lookup(name) netmap.Action`): the device's effective list (own rules, then preset or space rules) read by name: `domain` exact, `domain-suffix` the name and below, `default` everything; address matchers (`local`, `cidr`, `geoip`) are passed over; `geosite` and unknown matchers match nothing and, unless direct, turn later direct rules off; an unknown action or a chain that can't carry traffic blocks; no match blocks; no rules at all is direct (as routing). First match wins by position, O(labels) per lookup.
- **Resolver** (`internal/dataplane/dns`, `miekg/dns`): `dns.New(Options{Upstreams, Control, TunnelControl, Port, TunnelPort, Timeout, CacheSize, Log})`, `Update(Config{Listen, Clients, Zone, Names, Overlay, Route})`, `Counters()`, `Close()`. UDP and TCP on each overlay address; refuses sources outside `Clients`; answers `<label>.<zone>` A/AAAA (TTL 30) and PTR for overlay addresses; NXDOMAIN for any other `.internal` name and unknown overlay reverse names, never forwarded; otherwise by `Route`: direct → `Upstreams` in order, tunnel → the exit's overlay addresses at `TunnelPort` (53), block → SERVFAIL. UDP upstream with EDNS 1232, TCP on truncation, the next upstream on failure; forwarded queries carry only our own OPT (DO bit), none of the client's options; answers fit the client (512 without EDNS, at most 1232). Cache: LRU of 2048 answers ≤ 4 KiB each, keyed by question, DO/CD and route (a direct answer is never served for a tunnel-bound name), TTL capped at 1 h (negative: SOA's, at most 5 min, else 30 s), flushed on every `Update`. At most 256 queries forwarded at once. Logs never carry a name or an answer, only a failure to listen (an overlay address).
- **Engine** (`EngineConfig.DNS interface{ Update(dns.Config) }`, `internal/dataplane/resolver.go`): after every Apply (also a failed one, so revocations reach DNS), `SetRules` and `ReloadRules`: a device's resolver listens on its carried overlay addresses for its own addresses only, serves its own name and the names of the peers WireGuard has now (a removed peer leaves DNS with it; a name two peers claim names neither), and routes names by `CompileNames` with the chains whose exit is a usable peer (tunnel via the exit's addresses); an exit (server with `AllowEgress`) listens for the space's overlay networks and sends everything to its upstream; other servers don't listen.
- **OS integration** (`dns.SetSystem`, `dns.SystemUpstreams`, Linux `linux && !android`; elsewhere an error): systemd-resolved over D-Bus (`godbus/dbus/v5`) when `/etc/resolv.conf` names only resolved's stub and resolved owns its bus name: the TUN link gets the resolver's addresses, domains `~.` (every name) plus the zone as search domain, default route, LLMNR/mDNS/DoT/DNSSEC off; `RevertLink` on restore (resolved also forgets the link when the TUN goes). Otherwise `/etc/resolv.conf` is rewritten in place (it is often a bind mount): our nameservers, `search <zone> <original search>`, the original options, and the original file (or symlink target) in `#thinkpol-original` comment lines, so it comes back after a crash or reboot with nothing kept elsewhere; a watcher (2 s) takes the file back if another program rewrites it, taking the new content as the original. `SystemUpstreams` reads the original nameservers, or resolved's `/run/systemd/resolve/resolv.conf` behind the stub, never the stub or the node's own addresses.
- **Agent** (`thinkpol up -dns` default on, `-dns-upstream ip[:port],…`; `THINKPOL_DNS`, `THINKPOL_DNS_UPSTREAM`): `RunDataPlane` makes a resolver per start (upstreams: configured, else the OS's read before it is touched), passes it to the engine, and on a device points the OS at it after the first Apply, re-points it when the servers or zone change, and restores the OS's configuration first thing on disconnect or stop. A device asks exits with sockets bound to the TUN (`dns.BindToInterface`, `SO_BINDTODEVICE`), so a tunnel-bound query leaves through the tunnel or not at all (`TestTunnelQueriesLeaveThroughTheirInterfaceOnly`, in the lab). Server mode: the supervisor passes the worker `WorkerConfig.DNS` and `DNSUpstreams` (configured, else the host's non-loopback resolvers). Resolver counters go into the debug status line.
- **Lab:** `labdns` (built into `lab/bin`) stands in for resolvers out in the world; the lab image gains `dbus-daemon` and `systemd-resolved` (started only by tests that need them). `TestUpRunsTheM0Space` now checks `/etc/resolv.conf` is restored and leaves it out of its "nothing written" check (DESIGN "Node safety" says a connected device rewrites it).
- **Docs:** DESIGN.md "Routing rules and DNS" (names, rules by name, upstreams, OS integration, cache, logging) and "Node safety" (devices' sections name their peers; resolv.conf); `lab/README.md`.

**Decisions and limits:**
- The domestic upstream is local configuration or what the OS used before, not a map field: the controller can add one later (a section field) without changing the resolver.
- In the lab the exit runs `-mode device`: a worker's own queries to its upstream leave its namespace only once TP-014 forwards and masquerades a worker's traffic (see below).
- Blocked and fail-closed names answer SERVFAIL (not NXDOMAIN, which apps cache): a chain that comes back works at once.
- glibc's search list applies to dotted names that fail (`ndots:1`): `x.lab.internal` that doesn't exist is also tried as `x.lab.internal.<search domain>`, which then goes by the rules. Through systemd-resolved, names under a physical link's own search or routing domains (e.g. a DHCP `lan`) still go to that link's DNS server: resolved's routing, LAN names only.
- `TestADeviceConnectsAndDisconnects` (`internal/agent`) flakes under `-race` on `rewrite` too (5 of 40 runs at the TP-017 merge base): the status is read between the engine's stop and the removal being published. The udp and supervisor conformance tests time out now and then under a loaded host (`ShapingRefused`); both pass alone.

**For downstream tickets:**
- **TP-018 (route table):** set `dns.Options.Control` in `agent.(*runner).newResolver` to the links' socket Control (mark), so direct upstream queries leave around the tunnel; a `direct` domain rule doesn't route its answers' addresses (address rules do). Lab: in `TestDNSFollowsTheRules`, the domestic resolver's address must stay reachable when everything else enters the TUN.
- **TP-014 (egress):** once a worker's own traffic from its transit address is forwarded and masqueraded on egress-on servers, run server-1 in server mode in `TestDNSFollowsTheRules` (drop `-mode device`): the exit's resolver runs in the worker and asks `WorkerConfig.DNSUpstreams`.
- **TP-019 (macOS):** `dns.SetSystem` (scutil, or `/etc/resolver/<zone>` plus the default resolver), `dns.SystemUpstreams`, and `dns.BindToInterface` (`IP_BOUND_IF`/`IPV6_BOUND_IF`) for darwin; today they fail there, so tunnel-bound names fail closed. Acceptance moved there: overlay names resolve on macOS (manual checklist).
- **TP-021 (IPv6):** while IPv6 is blocked, the device's resolver still forwards AAAA questions; consider answering them empty (a flag in `dns.Config`) so apps don't try IPv6 first.
- **TP-022 / TP-041:** `dns.Counters` (queries, refused, overlay, direct, tunnel, blocked, cache hits, failed) are figures only, safe for status and telemetry; not in the local API yet.
- **TP-034/TP-035 (controller):** write the space's name and nodes' names into devices' sections only, as DNS labels unique in the section (`netmap.CheckLabel`).
- **TP-023 (M1 acceptance):** `TestDNSFollowsTheRules` is the DNS leak check.

## Log
- 2026-10-10 created in backlog
- 2026-10-12 backlog → in-progress — owner: agent-tp-020, branch: tp-020-dns-resolver
- 2026-10-12 docs: DESIGN.md "Routing rules and DNS" (names, rules by name, upstreams, OS integration, cache, logging) and "Node safety" (devices' sections name their peers; a connected device rewrites resolv.conf); acceptance's macOS half moved to TP-019 (its `needs_human: macos` checklist), see Notes
- 2026-10-12 merged origin/rewrite (TP-017)
- 2026-10-12 in-progress → review — acceptance checked; `make lint`, `make test`, `go test -race` on dataplane, agent, netmap and devmap, and `make lab-test` (lab tests and 26 packages in lab nodes) pass
