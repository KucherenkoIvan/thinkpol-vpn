---
id: TP-048
title: "Kill switch (macOS and Linux)"
milestone: M2
area: dataplane/firewall
repo: thinkpol-vpn
size: L
depends_on: [TP-046, TP-021, TP-078, TP-091]
refs: [D4]
needs_human: macos
owner: ""
branch: ""
---

## Goal
With the kill switch on, nothing leaves the device when the tunnel is down.

## Scope
- Firewall rules per OS: pf anchor (macOS), nftables (Linux): only entry endpoints allowed, plus LAN with allow-LAN.
- Temporary pause for captive portals.
- Rules stay in place if the service crashes, until it restores them.

## Acceptance
- [ ] with the service from TP-046, a simulated agent crash keeps traffic fail-closed until the restarted agent is back (macOS and Linux)
- [ ] killing the service with the kill switch on leaves no traffic flowing except to entries, on macOS and Linux
- [ ] after the agent crashes (killed, not stopped) with the "everything" or "all but domestic" preset and the kill switch off, nothing leaves except traffic to entries (and LAN with allow-LAN) until the agent starts and connects again, on macOS and Linux; opt-out is a setting
- [ ] a deliberate disconnect with the kill switch off removes the guard and traffic flows direct; with the switch on it stays

## Notes
- A pf guard for macOS doesn't exist yet; it comes with TP-078 (split from TP-021).
- **From TP-014 (egress):** an exit without IPv6 refuses a device's IPv6 with ICMPv6 "no route" rather than dropping it; the kill switch still has to block IPv6 outside the tunnel on the device, and must let the tunnel's own transport sockets out whatever the rules.

- **From TP-057 (route table):** sockets bound to an interface (`SO_BINDTODEVICE`, `IP_UNICAST_IF`, an `IP_PKTINFO` ifindex) bypass the route table by design (gateways must resolve on the physical side); while connected they leave by main's default route, both families. Only the firewall can confine them: allow the mark 0x7470 and the entries, direct destinations and (with allow-LAN) the LAN, drop the rest on physical interfaces. `routetable.TestGatewaysOnLinksAndBoundSockets` documents today's behaviour. Also: IPv4's unreachable default in table 0x7470 is there only while the TUN is down (TP-057), so after a crash IPv4 flows; with the kill switch on, the firewall keeps it in.
- **Crash posture (independent design review, 2026-10-13; TP-062).** Fail-closed after an agent crash is the default for the "everything" and "all but domestic" presets (opt-out); a deliberate disconnect still follows the kill-switch toggle (PRD D4, off by default). Today's behaviour, from TP-018 (done): after a crash IPv4 flows and IPv6 is unreachable but for direct destinations. The firewall rules therefore stay after a crash for those presets even with the toggle off, and are removed on a deliberate disconnect; macOS must meet this too (DESIGN "Desktop client", "Kill switch"). TP-019 (macOS data plane) is in review, so its ticket isn't changed: this ticket and TP-046 carry the note.
- **From TP-021 (IPv6 leak guard, Linux; corrected in its review):** the kill switch is a separate owner from the IPv6 leak guard and shares only the shape of `routetable.Exempt` (TUN, Mark, Direct, Upstreams). The guard is the route table's: `firewall.IPv6Guard`, table `inet thinkpol-guard`, applied by the Enforcer with the routes and removed with them, so it lives and dies with the connection. The kill switch gets its own table (`inet thinkpol-killswitch`) with its own `exempt4`/`exempt6` sets, applied by the agent from the toggle and the preset, and it survives a disconnect (and, per the crash posture below, a crash). Its chain must also sit late in output (the guard hooks at NF_IP6_PRI_LAST so no route chain re-marks after it), exempt neighbour discovery and MLD only with their hop limits (255, 1), and, on macOS, exempt the direct DNS upstreams by address (no socket mark there). `TestGatewaysOnLinksAndBoundSockets` still shows IPv4 bound sockets leaving by main's default route.

## Log
- 2026-10-10 created in backlog
- 2026-10-12 docs (TP-014 review): notes from egress on Linux
- 2026-10-12 docs (TP-057 review): interface-bound sockets are the firewall's to confine
- 2026-10-13 docs (TP-062): crash posture: fail-closed by default under the everything and all-but-domestic presets
- 2026-10-14 docs (TP-021): notes from the IPv6 leak guard on Linux
- 2026-10-14 docs (TP-021 review): the kill switch is its own owner and table; only Exempt's shape is shared
- 2026-10-15 docs (independent review 2026-10-15): retitled to macOS and Linux; milestone M2; depends on TP-021 not TP-047; needs_human macos; Windows/WFP moved to TP-076; note on missing macOS pf guard
- 2026-10-15 docs (TP-078 split): depends on the macOS pf IPv6 leak guard
- 2026-10-15 docs (backlog grooming, review fixes): acceptance for fail-closed gap after crash with TP-046 service
- 2026-10-16 docs (device testing rethink): depends on TP-091, whose `diag` snapshot is the evidence for its device run
