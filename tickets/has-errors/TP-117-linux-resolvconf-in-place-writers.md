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

## Review findings
Round 1 (2026-11-12):
- [ ] R1.1 (blocker) the settle has no upper bound: a writer rewriting resolv.conf every <500 ms keeps the host on its resolver indefinitely while Problem says protected. Cap the settle at a deadline set when it begins; Problem reports ErrUnprotected while a foreign file has been in place longer than the settle; a file swapped in whole (another inode) is taken at once
- [ ] R1.2 (should-fix) Update applies over a half-written foreign file the watch hasn't noticed yet: Update reads the file under the lock and leaves an in-place write to the watch; the initial take-over's race named in RR5 and the package doc
- [ ] R1.3 (should-fix) a deferred Update's apply error disappears: the watch logs apply errors, System.Update documents the deferral, a later failure reaches Problem; Update after Restore returns an error, and Restore no longer resets the settle
- [ ] R1.4 (should-fix, design) the watch's state machine: explicit cases, the quiet timer, correct comments; fileState a comparable struct; apply takes the read the watch judged
- [ ] R1.5 (should-fix, design) adopt lines appended to the managed file as part of the original, as a backstop with the settle; tests for a slow writer past the cap and a hand append; doc.go rewritten
- [ ] R1.6 (should-fix, tests) the poll test's writer outlasts the settle; an identical-content writer; the Update test by timing, not private state; the inotify test's margin; a lab-gated bind-mount test of the node's own in-place write
- [ ] R1.7 (should-fix, docs and ticket) RR4's timing; RR5's reporting; the decision in Notes; doc.go's writers cited accurately; comments; the Log's counts and the branch; writeInPlaceSlowly's first pause

## Notes
- Found by TP-115's round-1 correctness review (2026-10-21). The loss predates TP-115.
- From TP-128's round-1 review (2026-10-22), more cases with the same cause:
  - The 2 s poll can read the file empty mid-rewrite. The empty content is then recorded as the original, so `Restore` would put back an empty resolv.conf. (Fixed in TP-117: a write in place settles before it is read.)
  - While the first read is owed, a managed link's target that reads empty (`linkedOriginal`) counts as a good read, the same ambiguity TP-128 settled the other way for resolved's uplink file. (Fixed in TP-117: an empty target is no read.)
  - An empty /etc/resolv.conf can be a valid configuration, so the rule here needs its own decision in the dns package doc, not a copy of the uplink rule.
  - RESIDUAL-RISKS RR5 should name losing the original, not only stale upstreams.
- Decision (2026-11-12, after round 1; RR5 is decided on it): another program's write of /etc/resolv.conf is taken back by how it was written. A file swapped in whole (another file than the one the node wrote: a rename, a new file) is complete and taken at once. A write into the node's file in place, or where that can't be told (no file; a bind mount), settles: read once it has been quiet (no change event, the same file state) for 500 ms, and never later than 2 s after the settle began, so a writer that never goes quiet doesn't keep the OS on its resolver; Problem reports ErrUnprotected while such a file has been in place longer than the settle. Lines appended to the managed file join the original, as a backstop behind the settle (an in-place writer still appending after its settle ended, a hand append), not instead of it. Update reads the file under the lock and leaves a write in place to the watch; a failure then shows in Problem and the log. The first take-over at start is not settled (nothing the node wrote tells a write in progress from a finished one); the backstop catches an appending writer's later lines there. What is left: a writer that writes through one open file and pauses past the settle or the cap, or is mid-write at start, has the part read taken as the original (RR5). The empty-file rules are unchanged: an empty /etc/resolv.conf that stays through the settle is the new original; an empty link target while the first read is owed is no read.

## Log
- 2026-10-21 created in backlog (TP-115 review round 1)
- 2026-10-22 docs (TP-128 review): the empty-read cases, Restore putting back an empty file, and RR5
- 2026-11-09 backlog → in-progress — owner: agent-tp-117, branch: tp-117-linux-resolvconf-in-place-writers
- 2026-11-12 continued from the stopped run's draft (kept after review, three fixes: the watch reads the file under the lock so its own in-place write on a bind mount never looks foreign; Restore cleared the settle so a later Update applied, which re-managed the file with no watch (replaced in round 1, R1.3: an Update after Restore returns an error); the test helper waited for a tell that never comes)
- 2026-11-12 decided: a 500 ms quiet period (no change event, same file state) before another program's write is read, and an Update during it is applied by the watch with the settled file; lines appended to the managed file as a new original rejected (it still reads the truncated file first, and would take a hand edit for a rewrite). An empty /etc/resolv.conf that stays empty through the settle is the new original (ErrNoSystemUpstream, Restore puts it back empty); an empty link target while the first read is owed is no read. Reasons in the dns package doc; RR5 names losing the original and is decided
- 2026-11-12 tests (resolvconf_settle_test.go): the inotify truncate-then-append writer (runs in the lab node, skips on macOS), the poll reading the file empty mid-write, an Update during a settle, an empty file that stays, an empty link target. Mutations, each failing its test: the settle switched off (`… && false`; the poll and Update tests on macOS, the inotify test in the lab node); Update ignoring the settle; linkedOriginal taking an empty target; an empty file never settling
- 2026-11-12 lab: no separate lab test; the dns package's unit tests run in a lab node under make lab-test, where the inotify test drives real inotify with a real truncate-then-append writer, which is what a busybox udhcpc script does to the file
- 2026-11-12 make test green; make lint green except vulncheck, which fails on every branch: GO-2026-6859 in net/http@go1.26.10 (fixed in go1.26.11, the toolchain in go.mod is go1.26.10), out of scope
- 2026-11-12 make lab-test green on cf24133 (38 packages in lab nodes plus the lab phase); the lint box stays open only for the vulncheck finding above (toolchain bump, out of scope)
- 2026-11-12 in-progress → review
- 2026-11-12 review → has-errors (round 1 findings R1.x)
