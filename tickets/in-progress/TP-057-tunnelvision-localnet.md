---
id: TP-057
title: "Route table: close LocalNet and overlay TunnelVision paths"
milestone: M1
area: dataplane/routetable
repo: thinkpol-vpn
size: M
depends_on: [TP-018]
refs: [R2, D6, DESIGN#routing-rules-and-dns]
owner: "agent-tp-018"
branch: "tp-057-tunnelvision-localnet"
---

## Goal
No route the local network can plant (DHCP addresses and classless routes, router advertisements, PPP peers) takes foreign or overlay traffic around the tunnel on a Linux device in route-table mode.

## Scope
1. **LocalNet (TunnelCrack).** A censor's DHCP can assign e.g. 1.1.1.50/24 (the kernel adds 1.1.1.0/24 on-link) or a PPP peer /32; kernel-processed router advertisements add on-link routes for any advertised prefix (e.g. 2001:4860:4860::/64). `TrustedOnLink` trusts only on-link subnets entirely inside `lists.Local()` (RFC 1918, link-local, ULA); the length rule goes. DESIGN states the cost: hosts on a public on-link LAN go through the tunnel unless the rules send them direct (a later setting could opt in).
2. **Overlay TunnelVision.** The overlay is never looked up in main: table 0x7470 gets `<overlay> dev <TUN>` and `unreachable <overlay>` (metric 2048), and the overlay's rule becomes `to <overlay> lookup 0x7470`, ahead of the on-link mirror rules, without a mark condition. Trusted on-link subnets overlapping the overlay are dropped.
3. **Crash, then a failed start:** clear the route table when a device goes down with no engine running, and in start-failure paths before an Enforcer exists.
4. After the watcher restarts following an Enforce, re-apply once, in case events were missed meanwhile.
5. A kernel without rule protocols (`ErrUnsupported`) is terminal for the route table: no retry loop; the status says so.
6. Fix TP-018's stale done-ticket Notes.
7. Check that vishvananda/netlink's RuleList round-trips absent SuppressPrefixlen/Goto/Flow as -1, so rule 5301 isn't re-added on every re-apply.

## Out of scope
An opt-in to keep a public on-link LAN out of the tunnel (a later setting); firewall-level leak blocking (TP-021, TP-048).

## Acceptance
- [ ] namespace tests: with 198.51.100.50/24 on the physical interface and an RA-style on-link 2001:db8:ab::/64, foreign destinations in those ranges still enter the TUN
- [ ] namespace tests: with an option-121-style 100.64.0.0/24 via the LAN gateway, an address inside the overlay /16 on the physical interface, and an on-link prefix inside the overlay's IPv6 /48, overlay traffic still enters the TUN
- [ ] lab: a crash, then a start that fails, leaves no route-table rules or routes
- [ ] a kernel without rule protocols stops the route table for good, visible in the status

## Notes
- From the post-merge leak check of TP-018 (orchestrator decisions 1–6 above).

## Log
- 2026-10-12 created in in-progress — owner: agent-tp-018, branch: tp-057-tunnelvision-localnet (follow-up to TP-018's post-merge leak check)
