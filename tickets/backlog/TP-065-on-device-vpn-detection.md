---
id: TP-065
title: "On-device VPN detection: what local apps can observe and mitigations"
milestone: later
area: research
repo: thinkpol-vpn
size: M
depends_on: []
refs: [docs/design/security.md#threat-model]
owner: ""
branch: ""
---

## Goal
Government-affiliated apps installed on members' devices can probe whether blocked services are reachable and look for VPN state (interfaces, routes, DNS, reachability). This ticket says exactly what a local app can observe on each OS the client targets, what thinkpol can and can't hide, and which mitigations are worth building (independent design review, 2026-10-13).

## Scope
- Per OS (macOS, Linux, Windows, Android): the observable signals: a TUN/utun interface and its name, routes and rules, DNS configuration, reachability and latency of blocked destinations, the platform's VPN APIs (Android's VpnService is detectable by design), process and network-extension lists.
- What each mitigation buys: "all but domestic" keeps domestic apps on the domestic path; per-app split tunnelling in userspace mode (R8) is the later mitigation; interface naming; anything else found.
- What can't be hidden, written down plainly for the threat model.

## Out of scope
- Implementing any mitigation: tickets from the findings.

## Acceptance
- [ ] a findings note in Notes: per OS, what is observable and what is mitigable
- [ ] DESIGN.md's threat-model row on apps on a member's device and the PRD risk are updated to match

## Log
- 2026-10-13 created in backlog (TP-062)
