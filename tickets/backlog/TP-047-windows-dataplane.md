---
id: TP-047
title: "Windows data plane"
milestone: M5
area: platform/windows
repo: thinkpol-vpn
size: epic
depends_on: [TP-019, TP-021]
refs: [D1]
needs_human: windows
owner: ""
branch: ""
---

## Goal
The device data plane runs on Windows.

## Scope (split before starting)
- Wintun via `wireguard-go/tun`.
- netcfg adapter (e.g. `winipcfg` from wireguard-windows).
- Route-table enforcement: big route tables are slow on Windows; measure, consider a WFP-based alternative.
- DNS through NRPT; IPv6 leak prevention.
- Local API over a named pipe (check KRN-001 covers it).

## Log
- 2026-10-10 created in backlog
