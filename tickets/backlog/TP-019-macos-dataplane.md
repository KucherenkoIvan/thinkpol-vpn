---
id: TP-019
title: "macOS data plane"
milestone: M1
area: dataplane
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

## Notes
- **From TP-022:** the local API's macOS default is `/var/run/thinkpol-api/api.sock`, but `/var/run` (`/private/var/run`) is `root:daemon 0775`, which the API refuses as a parent (writable by a group): pick a root-only parent (e.g. a directory of the service's own under `/Library` or `/private/var/run/thinkpol`) and change `agent.DefaultAPISocket`. `peercred_darwin.go` (`LOCAL_PEERCRED`) has never run on a Mac. The pure-Go group lookup reads `/etc/group` only: pass the `thinkpol` group's gid (`THINKPOL_API_GROUP=<gid>`).

## Log
- 2026-10-10 created in backlog
