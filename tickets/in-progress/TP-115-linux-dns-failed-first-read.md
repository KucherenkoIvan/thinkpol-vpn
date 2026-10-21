---
id: TP-115
title: "Linux DNS: a failed first read of the system's resolvers stays silent"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: [TP-108]
refs: [DESIGN#routing-rules-and-dns]
owner: "cursor-glm-tp-115"
branch: "tp-115-linux-dns-failed-first-read"
---

## Goal
On Linux, as on macOS since TP-108, a device whose first read of the OS's resolvers failed reports `dns_upstreams_stale` and takes the first read that works.

## Scope
- The Linux adapters (`resolvConf`, `resolved`) ignore `dns.SystemConfig.UpstreamsUnknown`: they tell `Upstreams` only when `resolv.conf` (or resolved's uplink file) changes. After a failed first read (`internal/agent/resolver.go` newResolver), the resolver has no direct upstreams until that file changes, which on a stable network may be never, and health says nothing.
- With `UpstreamsUnknown` set: report `ErrUpstreamsStale` until a read works, read again on the adapter's existing watch/backstop, and tell the first good read whether or not it changed.
- The agent's warnings say the same thing on both OSes (`resolver.go`, `dataplane.go` comments mention macOS only).

## Acceptance
- [ ] unit tests with the Linux adapters' fakes: first read fails → stale; a later read works → told, stale cleared
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Found by TP-108's implementer and its round-5 correctness review (2026-10-19); TP-108's scope was macOS.

## Log
- 2026-10-19 created in backlog (TP-108 review round 5)
- 2026-10-21 backlog → in-progress — owner: cursor-glm-tp-115, branch: tp-115-linux-dns-failed-first-read
