---
id: TP-021
title: "IPv6 leak prevention"
milestone: M1
area: dataplane
repo: thinkpol-vpn
size: M
depends_on: [TP-018, TP-019]
refs: [D6, DESIGN#ipv6]
needs_human: macos
owner: "agent-tp-021"
branch: "tp-021-ipv6-leaks"
---

## Goal
While connected, IPv6 goes through the tunnel or is blocked; it never leaks around it.

## Scope
- If the egress supports IPv6: route IPv6 into the tunnel like IPv4.
- Otherwise: block IPv6 on physical interfaces while connected (Linux nftables, macOS pf anchor), except to entry endpoints.
- Restore on disconnect, also after a crash (next start cleans up).

## Acceptance
- [ ] lab capture and the macOS checklist: no IPv6 packet leaves a physical interface outside the tunnel while connected

## Notes
- **From TP-014 (egress):** an exit whose uplink has no IPv6 (no IPv6 default route, or only unique local addresses) refuses a device's IPv6 inside its namespace with ICMPv6 "no route", at once, and none leaves; the device must still keep IPv6 from going around the tunnel itself.

- **From TP-057 (route table):** sockets bound to an interface (`SO_BINDTODEVICE`, `IP_UNICAST_IF`, an `IP_PKTINFO` ifindex: `ping -I eth0`, NetworkManager's connectivity checks, systemd-resolved's per-link DNS) can't be confined by routing: IPv4 and IPv6 both leave by main's default route (the rule `oif <link> lookup main suppress_prefixlength 0` at 5298 exists so the kernel can resolve gateways, and IPv4 would otherwise reach on-link hosts by ARP anyway). Block them in the firewall while connected (e.g. nftables: output on a physical interface, not marked 0x7470, not to a direct destination, not to the LAN), at least for IPv6 here. `internal/dataplane/routetable` `TestGatewaysOnLinksAndBoundSockets` documents today's behaviour (`ip route get … oif eth0`): flip its assertions when the firewall lands.

## Log
- 2026-10-10 created in backlog
- 2026-10-12 docs (TP-014 review): notes from egress on Linux
- 2026-10-12 docs (TP-057 review): interface-bound sockets are the firewall's to confine
- 2026-10-14 backlog → in-progress — owner: agent-tp-021, branch: tp-021-ipv6-leaks (round 1: Linux; the orchestrator starts it while TP-019 is in review, macOS pf waits for its merge)
