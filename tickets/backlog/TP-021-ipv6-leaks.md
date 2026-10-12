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

## Notes
- **From TP-014 (egress):** an exit whose uplink has no IPv6 (no IPv6 default route, or only unique local addresses) refuses a device's IPv6 inside its namespace with ICMPv6 "no route", at once, and none leaves; the device must still keep IPv6 from going around the tunnel itself.

## Log
- 2026-10-10 created in backlog
- 2026-10-12 docs (TP-014 review): notes from egress on Linux
