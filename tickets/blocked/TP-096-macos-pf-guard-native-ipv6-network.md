---
id: TP-096
title: "macOS pf guard on a network with native IPv6"
milestone: M2
area: dataplane/firewall
repo: thinkpol-vpn
size: S
depends_on: [TP-078, TP-092, TP-097]
refs: [DESIGN#ipv6]
needs_human: macos
owner: ""
branch: ""
---

## Goal
On a Mac connected to a network with native IPv6, run TP-078's device checklist steps 0–10: bound `ping6`/`curl -6 --interface en0` refused, tcpdump on en0 clean, still refused after kill -9, clean after stop (`-connect=false`).

## Scope
- Record results in this ticket's Notes (device-test kit session B: checks 08a, 08, 09, 10, plus the leak-path steps that were UNKNOWN without native IPv6 in TP-078 sessions A and B).

## Out of scope
Lab emulation of native IPv6 on the host (host network stack is off limits).

## Acceptance
- [ ] steps 0–10 of TP-078's device checklist pass on a network with global IPv6 and a default IPv6 route, results in Notes
- [ ] `make lint` and `make test` pass (no code change required if the run is docs-only)

## Blocked by
The owner has no network with native IPv6 available now. Unblock when one is.

## Notes
- The device-test kit's session B (08a, 08, 09, 10) is ready for this run.

## Log
- 2026-10-16 created (TP-078/TP-092 device sessions)
- 2026-10-16 docs: can run in TP-097's VM lab (a router VM gives native IPv6), so it depends on TP-097
