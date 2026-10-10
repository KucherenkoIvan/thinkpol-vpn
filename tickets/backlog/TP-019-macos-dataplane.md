---
id: TP-019
title: "macOS data plane"
milestone: M1
area: platform/macos
repo: thinkpol-vpn
size: L
depends_on: [TP-008, TP-018]
refs: [D1]
needs_human: macos
owner: ""
branch: ""
---

## Goal
The device data plane runs on macOS with the same behaviour as on Linux.

## Scope
- utun via `wireguard-go/tun`.
- netcfg adapter for macOS: addresses, MTU, routes (route sockets via `golang.org/x/net/route`; `ifconfig`/`route` exec only as a documented fallback).
- Route-table enforcement parity with TP-018, including gateway change detection (Wi-Fi switches, sleep/wake).
- Runs as root through the CLI; installing as a service is TP-046.

## Acceptance
- [ ] manual checklist on the author's Mac, recorded in Notes: up, ping a server's overlay address, browse through an egress node, sleep/wake, Wi-Fi change, down leaves no routes

## Log
- 2026-10-10 created in backlog
