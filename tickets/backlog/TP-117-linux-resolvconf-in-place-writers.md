---
id: TP-117
title: "Linux DNS: an in-place writer of resolv.conf loses its lines"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: [TP-115]
refs: [DESIGN#routing-rules-and-dns]
owner: ""
branch: ""
---

## Goal
A DHCP client that rewrites `/etc/resolv.conf` in place while the node manages it doesn't lose its servers: the node takes the complete file as the new original.

## Scope
- Some writers truncate the file and then append to it: busybox udhcpc (`echo -n > $RESOLV_CONF`, then `echo nameserver … >> $RESOLV_CONF`), dhcpcd's `cat > /etc/resolv.conf`. The watch (`watch_linux.go`, `IN_CREATE|IN_CLOSE_WRITE`) wakes on the first close and `resolvConf.apply` reads the half-written file. It renames the managed file over it, so the writer's later appends land in the managed file, where `parseResolvConf` ignores them.
- Result: the original stays empty and the direct upstreams are lost until the next rewrite. With TP-115, an empty read while the first read is still owed also clears `dns_upstreams_stale`.
- Decide how to settle a write (for example a short quiet period after the last event before reading, or lines appended to the managed file taken as a new original), and test it with a fake writer that truncates then appends.

## Acceptance
- [ ] a unit test with a truncate-then-append writer: the node ends with the writer's servers as the original and tells them
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Found by TP-115's round-1 correctness review (2026-10-21). The loss predates TP-115.

## Log
- 2026-10-21 created in backlog (TP-115 review round 1)
