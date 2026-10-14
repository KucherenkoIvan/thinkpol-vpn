---
id: TP-048
title: "Kill switch"
milestone: M5
area: dataplane/firewall
repo: thinkpol-vpn
size: L
depends_on: [TP-046, TP-047]
refs: [D4]
needs_human: windows
owner: ""
branch: ""
---

## Goal
With the kill switch on, nothing leaves the device when the tunnel is down.

## Scope
- Firewall rules per OS: pf anchor (macOS), nftables (Linux), WFP (Windows): only entry endpoints allowed, plus LAN with allow-LAN.
- Temporary pause for captive portals.
- Rules stay in place if the service crashes, until it restores them.

## Acceptance
- [ ] killing the service with the kill switch on leaves no traffic flowing except to entries, on all three OSes
- [ ] after the agent crashes (killed, not stopped) with the "everything" or "all but domestic" preset and the kill switch off, nothing leaves except traffic to entries (and LAN with allow-LAN) until the agent starts and connects again, on all three OSes; opt-out is a setting
- [ ] a deliberate disconnect with the kill switch off removes the guard and traffic flows direct; with the switch on it stays

## Notes
- **From TP-014 (egress):** an exit without IPv6 refuses a device's IPv6 with ICMPv6 "no route" rather than dropping it; the kill switch still has to block IPv6 outside the tunnel on the device, and must let the tunnel's own transport sockets out whatever the rules.

- **From TP-057 (route table):** sockets bound to an interface (`SO_BINDTODEVICE`, `IP_UNICAST_IF`, an `IP_PKTINFO` ifindex) bypass the route table by design (gateways must resolve on the physical side); while connected they leave by main's default route, both families. Only the firewall can confine them: allow the mark 0x7470 and the entries, direct destinations and (with allow-LAN) the LAN, drop the rest on physical interfaces. `routetable.TestGatewaysOnLinksAndBoundSockets` documents today's behaviour. Also: IPv4's unreachable default in table 0x7470 is there only while the TUN is down (TP-057), so after a crash IPv4 flows; with the kill switch on, the firewall keeps it in.
- **Crash posture (independent design review, 2026-10-13; TP-062).** Fail-closed after an agent crash is the default for the "everything" and "all but domestic" presets (opt-out); a deliberate disconnect still follows the kill-switch toggle (PRD D4, off by default). Today's behaviour, from TP-018 (done): after a crash IPv4 flows and IPv6 is unreachable but for direct destinations. The firewall rules therefore stay after a crash for those presets even with the toggle off, and are removed on a deliberate disconnect; macOS must meet this too (DESIGN "Desktop client", "Kill switch"). TP-019 (macOS data plane) is in review, so its ticket isn't changed: this ticket and TP-046 carry the note.
- **From TP-021 (IPv6 leak guard, Linux):** IPv6's half of confining bound sockets exists: `firewall.IPv6Guard`, an nftables table `inet thinkpol-guard` applied by the route table's Enforcer after the routes (exempt: oifname lo and the TUN, mark 0x7470, an interval set of what the table throws, link-scoped IPv6, ND/MLD; TCP reset, else ICMPv6 admin-prohibited), removed on Close and by `routetable.Clear`, left in place by a crash. IPv4 passes it on purpose (`meta nfproto != ipv6 accept`): the kill switch can add IPv4 to the same table and set (`firewall.Exempt.Direct` already carries IPv4), with allow-LAN and the toggle deciding what survives a disconnect. `TestGatewaysOnLinksAndBoundSockets` still documents IPv4 bound sockets leaving by main's default.

## Log
- 2026-10-10 created in backlog
- 2026-10-12 docs (TP-014 review): notes from egress on Linux
- 2026-10-12 docs (TP-057 review): interface-bound sockets are the firewall's to confine
- 2026-10-13 docs (TP-062): crash posture: fail-closed by default under the everything and all-but-domestic presets
- 2026-10-14 docs (TP-021): notes from the IPv6 leak guard on Linux
