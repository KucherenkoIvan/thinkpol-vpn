---
id: TP-117
title: "Linux DNS: an in-place writer of resolv.conf loses its lines"
milestone: M2
area: dataplane
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-115]
refs: [docs/design/routing.md#routing-rules-and-dns]
owner: "agent-tp-117"
branch: "tp-117-linux-resolvconf-in-place-writers"
---

## Goal
A DHCP client that rewrites `/etc/resolv.conf` in place while the node manages it doesn't lose its servers: the node takes the complete file as the new original.

## Scope
- Some writers truncate the file and then append to it: busybox udhcpc (`echo -n > $RESOLV_CONF`, then `echo nameserver … >> $RESOLV_CONF`), dhcpcd's `cat > /etc/resolv.conf`. The watch (`watch_linux.go`, `IN_CREATE|IN_CLOSE_WRITE`) wakes on the first close and `resolvConf.apply` reads the half-written file. It renames the managed file over it, so the writer's later appends land in the managed file, where `parseResolvConf` ignores them.
- Result: the original stays empty and the direct upstreams are lost until the next rewrite. With TP-115, an empty read while the first read is still owed also clears `dns_upstreams_stale`.
- Decide how to settle a write (for example a short quiet period after the last event before reading, or lines appended to the managed file taken as a new original), and test it with a fake writer that truncates then appends.

## Acceptance
- [x] a unit test with a truncate-then-append writer: the node ends with the writer's servers as the original and tells them
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Found by TP-115's round-1 correctness review (2026-10-21). The loss predates TP-115.
- From TP-128's round-1 review (2026-10-22), more cases with the same cause:
  - The 2 s poll can read the file empty mid-rewrite. The empty content is then recorded as the original, so `Restore` would put back an empty resolv.conf.
  - While the first read is owed, a managed link's target that reads empty (`linkedOriginal`) counts as a good read, the same ambiguity TP-128 settled the other way for resolved's uplink file.
  - An empty /etc/resolv.conf can be a valid configuration, so the rule here needs its own decision in the dns package doc, not a copy of the uplink rule.
  - RESIDUAL-RISKS RR5 should name losing the original, not only stale upstreams.

## Log
- 2026-10-21 created in backlog (TP-115 review round 1)
- 2026-10-22 docs (TP-128 review): the empty-read cases, Restore putting back an empty file, and RR5
- 2026-11-09 backlog → in-progress, owner: agent-tp-117
- 2026-11-12 continued from the stopped run's draft (kept after review, two fixes: the watch reads the file under the lock so its own in-place write on a bind mount never looks foreign; Restore clears the settle so a later Update applies; the test helper waited for a tell that never comes)
- 2026-11-12 decided: a 500 ms quiet period (no change event, same file state) before another program's write is read, and an Update during it is applied by the watch with the settled file; lines appended to the managed file as a new original rejected (it still reads the truncated file first, and would take a hand edit for a rewrite). An empty /etc/resolv.conf that stays empty through the settle is the new original (ErrNoSystemUpstream, Restore puts it back empty); an empty link target while the first read is owed is no read. Reasons in the dns package doc; RR5 names losing the original and is decided
- 2026-11-12 tests (resolvconf_settle_test.go): the inotify truncate-then-append writer (runs in the lab node, skips on macOS), the poll reading the file empty mid-write, an Update during a settle, an empty file that stays, an empty link target. Mutations, each failing its test: the settle switched off (`… && false`; the poll and Update tests on macOS, the inotify test in the lab node); Update ignoring the settle; linkedOriginal taking an empty target; an empty file never settling
- 2026-11-12 lab: no separate lab test; the dns package's unit tests run in a lab node under make lab-test, where the inotify test drives real inotify with a real truncate-then-append writer, which is what a busybox udhcpc script does to the file
- 2026-11-12 make test green; make lint green except vulncheck, which fails on every branch: GO-2026-6859 in net/http@go1.26.10 (fixed in go1.26.11, the toolchain in go.mod is go1.26.10), out of scope
