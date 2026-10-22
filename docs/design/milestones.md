# thinkpol-vpn — Milestones

The milestones' technical done-when checks, and what is out of scope for now. The entry point is [DESIGN.md](../../DESIGN.md); `RRn` are rows of [RESIDUAL-RISKS.md](../../RESIDUAL-RISKS.md).

## Milestones

Scope per milestone is in [PRD.md](../../PRD.md#release-plan); these are the technical "done" checks.

| | Milestone | Done when |
|---|---|---|
| M0 | Two Linux nodes in the lab, hand-made map in the sealed-section format, `udp` transport, relay paths; server agent as supervisor + one worker in its own namespace | `ping` directly (device ↔ server) and device ↔ device via a relay, over IPv4 and IPv6 ([lab/M0.md](../../lab/M0.md)) |
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
