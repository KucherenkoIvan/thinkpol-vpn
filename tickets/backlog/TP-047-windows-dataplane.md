---
id: TP-047
title: "Windows data plane"
milestone: M5
area: dataplane
repo: thinkpol-vpn
size: epic
depends_on: [TP-019, TP-021, TP-075]
refs: [D1]
needs_human: windows
owner: ""
branch: ""
---

## Goal
The device data plane runs on Windows.

## Scope (split before starting)
- Windows service install and connect-on-boot (moved from TP-046; macOS and Linux stay in TP-046).
- Wintun via `wireguard-go/tun`.
- netcfg adapter (e.g. `winipcfg` from wireguard-windows).
- Route-table enforcement: big route tables are slow on Windows; measure, consider a WFP-based alternative.
- DNS through NRPT; IPv6 leak prevention.
- Local API over a named pipe (check KRN-001 covers it).

## Notes
- Split before starting (backlog grooming 2026-10-15).

## Log
- 2026-10-10 created in backlog
- 2026-10-15 docs (backlog grooming): depends on TP-075; Windows service scope from TP-046
