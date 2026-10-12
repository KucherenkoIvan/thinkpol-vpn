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
owner: "agent-tp-019"
branch: "tp-019-macos-data-plane"
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
- **Design (WIP, agent-tp-019, 2026-10-13)** — being implemented on this branch; final Notes replace this:
  - utun via `wgtun.CreateTUN("utun", mtu)` (the kernel picks the unit); the agent uses the TUN's real name (`dev.Name()`) everywhere after creation (DNS binding, blobs, OS resolver).
  - netcfg darwin adapter: routes over a PF_ROUTE socket (`golang.org/x/net/route` messages), RIB dumps by sysctl, addresses/MTU/flags by ioctl; no `ifconfig`/`route` exec. Ownership: every thinkpol route carries `RTF_PROTO2` *and* is listed in its owner's record file next to the owner's lock (`/var/run/thinkpol/netcfg`); both are required, because other software on real Macs uses `RTF_PROTO1` (another VPN client's split routes carry it) and the kernel itself uses `RTF_PROTO3` (RTPRF_OURS on cloned routes). Cloned (`RTF_WASCLONED`) and scoped (`RTF_IFSCOPE`) routes are never ours, never conflicts. utun is point-to-point: the adapter adds the overlay networks' "connected" routes itself (owned like any route) unless the kernel made one.
  - Route table on macOS (no policy routing): main table only. IPv4 `0/1`+`128/1` into the utun (reject routes while the TUN is down); IPv6 `::/2`×4 into the utun with reject `::/1`+`8000::/1` behind (so IPv6 stays blocked after a crash, as on Linux), or the rejects only when the overlay doesn't carry IPv6. Direct prefixes and endpoints via the physical default gateway (on-link where they lie inside an on-link subnet), re-applied from a route-socket watcher on gateway/interface changes. TunnelVision/LocalNet: untrusted on-link subnets and foreign more-specific routes over tunneled space are shadowed by more-specific routes into the utun (gateways, direct and endpoints excluded); foreign host routes can't be shadowed and are counted as "ahead" in the status.
  - Socket binding: `IP_BOUND_IF`/`IPV6_BOUND_IF` — links and the direct DNS upstream to the current default route's interface (looked up per socket, so a redialed link follows roaming), tunnel DNS and blobs to the utun.
  - DNS: SystemConfiguration dynamic store through `/usr/sbin/scutil` (pure Go, no cgo): every active network service's `State:` DNS (and `Setup:` where manual DNS exists) is overridden with the overlay resolver, originals kept in the store itself for crash recovery (the store is per boot, like the overrides), polled and re-applied when the system republishes; other software's supplemental resolvers are reported as `dns_not_protected`.
  - Local API default socket: `/var/db/thinkpol-api/api.sock` (the whole parent chain is root:wheel 0755).

## Log
- 2026-10-10 created in backlog
- 2026-10-13 backlog → in-progress — owner: agent-tp-019, branch: tp-019-macos-data-plane
