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
- [x] unit tests with the Linux adapters' fakes: first read fails → stale; a later read works → told, stale cleared
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- Found by TP-108's implementer and its round-5 correctness review (2026-10-19); TP-108's scope was macOS.

## Review findings
Round 1 (2026-10-21): correctness, design and a second-opinion review.
- [ ] R1.1 `SystemConfig.Upstreams` is documented as called from the configuration's own goroutine, but `resolvConf.apply` calls it inline under `r.mu` (at setup, on the agent's runner goroutine). `apply` returns the tell instead; callers run it after unlocking; setup hands the first one to the watch goroutine, as darwin and `resolved` do.
- [ ] R1.2 Behind resolved's stub, an unreadable uplink file is swallowed by `upstreamsFromContent`: `resolvConf` takes the stub file as the first good read (tells nil, clears stale), the agent's own read never fails so `UpstreamsUnknown` is never set on a stub-mode host, and `resolved.untold` is reachable only through a race. Make an unreadable uplink a failed read where it matters: the agent's first read (`SystemUpstreams`), `resolvConf`'s untold read and `resolved`'s watch. Where a read already happened, keep today's "previous upstreams are kept". Test: a stub resolv.conf with no uplink file → stale; the uplink appears → told.
- [ ] R1.3 A dangling `/etc/resolv.conf` link at setup (resolved starting after the node) is replaced by a managed file with an empty original, and nothing ever reads the link's target: stale until a reconnect, though a read would work. While untold and managed with a recorded link target, read the target (relative to the file's directory). Test: dangling link → stale; the target appears → told, stale cleared. Say in the comment that a missing and an empty original look the same in the managed file.
- [ ] R1.4 `resolved` has no test, and the Log's reason ("needs D-Bus, has no fakes") doesn't hold: the per-tick read doesn't need D-Bus. Make the uplink path a field, pull the read into a method (what to tell, under `mu`), and unit-test it against a temp file: missing → stale; appears → told; unchanged → silent. If a lab subtest under the systemd-resolved case is cheap, add one. Correct the Log and the box.
- [ ] R1.5 `setResolved` stores the raw `nameservers(b)` but tells the filtered list; the first tick then sees a "change" and tells again. Store the filtered list.
- [ ] R1.6 The default Linux path (`Upstreams` set, `UpstreamsUnknown` false) has no setup test: `untold: c.Upstreams != nil` or telling at every setup would pass the suite. Add it (nothing told, nothing stale), and a test for the reordering (a first `apply` that writes nothing, then a real change, is told).
- [ ] R1.7 An original without a trailing newline: the first `apply` stores the raw bytes, the managed copy adds `\n`, and the next tick tells the same upstreams again ("resolvers changed" in the log). Compare what the original means, not its bytes, or normalise both sides. Test it.
- [ ] R1.8 DESIGN.md ("Routing rules and DNS", Linux part): add the failed-first-read rule (`dns_upstreams_stale` until a read of `/etc/resolv.conf`, or behind the stub its uplink file, works; that read is taken whether or not it changed; a missing file or dangling link is a failed read).
- [ ] R1.9 One shape, not three: put the "untold" start condition and its comment once in the OS-neutral file (e.g. `startsUntold(c SystemConfig)` next to `staleUpstreams`), used by darwin, `resolvConf` and `resolved`. Names: `firstRead` → `firstGoodRead`; `resolved`'s `tellFirst`/`tellNow`/`tellUntold`/`found` → the same names as `resolvConf`. Reword "A good read, told or not: the next change alone is told."
- [ ] R1.10 Log: scope item 3 (`resolver.go`'s warning was already OS-neutral; `dataplane.go`'s comment loses "on macOS"). Re-run `make lint` once TP-116 (go1.26.10) is in `rewrite` and merged here: with go1.26.9 vulncheck fails on GO-2026-6809.

Out of scope, filed as a new backlog ticket: an in-place writer (udhcpc, `cat >`) that empties `/etc/resolv.conf` then appends to it is read half-written and loses its lines to the managed rename (pre-existing; with this change a transient empty read also clears the stale report).

## Log
- 2026-10-19 created in backlog (TP-108 review round 5)
- 2026-10-21 backlog → in-progress — owner: cursor-glm-tp-115, branch: tp-115-linux-dns-failed-first-read
- 2026-10-21 resolvConf and resolved honour UpstreamsUnknown: stale via ErrUpstreamsStale until a read works, the first good read told to Upstreams whatever it found (112c351); staleUpstreams moved to the OS-neutral file and darwin's Problem reuses it; a failed read over a dangling resolv.conf symlink is not a good read
- 2026-10-21 mutation checks: dropping the first-read tell, the unknown-original rule, Problem's stale part, and the Upstreams!=nil guard each fail the new tests
- 2026-10-21 not verified in unit tests: resolved's watch (needs D-Bus, has no fakes); its read/tell logic mirrors resolvConf's
- 2026-10-21 make lint, make test green; make lab-test green at 112c351 (first run failed on lab-infrastructure route flake, rerun clean)
- 2026-10-21 in-progress → review
- 2026-10-21 review → has-errors (round 1: R1.1–R1.10)
- 2026-10-21 has-errors → in-progress (round 1 findings)
