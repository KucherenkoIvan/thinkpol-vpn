---
id: TP-021
title: "IPv6 leak prevention"
milestone: M1
area: dataplane
repo: thinkpol-vpn
size: M
depends_on: [TP-018, TP-019]
refs: [D6, DESIGN#ipv6]
owner: ""
branch: ""
---

## Goal
While connected, IPv6 goes through the tunnel or is blocked; it never leaks around it.

## Scope
- If the egress supports IPv6: route IPv6 into the tunnel like IPv4.
- Otherwise: block IPv6 on physical interfaces while connected (Linux nftables, macOS pf anchor), except to entry endpoints.
- Restore on disconnect, also after a crash (next start cleans up).

## Acceptance
- [ ] lab capture and the macOS checklist: no IPv6 packet leaves a physical interface outside the tunnel while connected

## Log
- 2026-10-10 created in backlog
