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
- [x] R1.1 `SystemConfig.Upstreams` is documented as called from the configuration's own goroutine, but `resolvConf.apply` calls it inline under `r.mu` (at setup, on the agent's runner goroutine). `apply` returns the tell instead; callers run it after unlocking; setup hands the first one to the watch goroutine, as darwin and `resolved` do.
- [x] R1.2 Behind resolved's stub, an unreadable uplink file is swallowed by `upstreamsFromContent`: `resolvConf` takes the stub file as the first good read (tells nil, clears stale), the agent's own read never fails so `UpstreamsUnknown` is never set on a stub-mode host, and `resolved.untold` is reachable only through a race. Make an unreadable uplink a failed read where it matters: the agent's first read (`SystemUpstreams`), `resolvConf`'s untold read and `resolved`'s watch. Where a read already happened, keep today's "previous upstreams are kept". Test: a stub resolv.conf with no uplink file → stale; the uplink appears → told.
- [x] R1.3 A dangling `/etc/resolv.conf` link at setup (resolved starting after the node) is replaced by a managed file with an empty original, and nothing ever reads the link's target: stale until a reconnect, though a read would work. While untold and managed with a recorded link target, read the target (relative to the file's directory). Test: dangling link → stale; the target appears → told, stale cleared. Say in the comment that a missing and an empty original look the same in the managed file.
- [x] R1.4 `resolved` has no test, and the Log's reason ("needs D-Bus, has no fakes") doesn't hold: the per-tick read doesn't need D-Bus. Make the uplink path a field, pull the read into a method (what to tell, under `mu`), and unit-test it against a temp file: missing → stale; appears → told; unchanged → silent. If a lab subtest under the systemd-resolved case is cheap, add one. Correct the Log and the box.
- [x] R1.5 `setResolved` stores the raw `nameservers(b)` but tells the filtered list; the first tick then sees a "change" and tells again. Store the filtered list.
- [x] R1.6 The default Linux path (`Upstreams` set, `UpstreamsUnknown` false) has no setup test: `untold: c.Upstreams != nil` or telling at every setup would pass the suite. Add it (nothing told, nothing stale), and a test for the reordering (a first `apply` that writes nothing, then a real change, is told).
- [x] R1.7 An original without a trailing newline: the first `apply` stores the raw bytes, the managed copy adds `\n`, and the next tick tells the same upstreams again ("resolvers changed" in the log). Compare what the original means, not its bytes, or normalise both sides. Test it.
- [x] R1.8 DESIGN.md ("Routing rules and DNS", Linux part): add the failed-first-read rule (`dns_upstreams_stale` until a read of `/etc/resolv.conf`, or behind the stub its uplink file, works; that read is taken whether or not it changed; a missing file or dangling link is a failed read).
- [x] R1.9 One shape, not three: put the "untold" start condition and its comment once in the OS-neutral file (e.g. `startsUntold(c SystemConfig)` next to `staleUpstreams`), used by darwin, `resolvConf` and `resolved`. Names: `firstRead` → `firstGoodRead`; `resolved`'s `tellFirst`/`tellNow`/`tellUntold`/`found` → the same names as `resolvConf`. Reword "A good read, told or not: the next change alone is told."
- [x] R1.10 Log: scope item 3 (`resolver.go`'s warning was already OS-neutral; `dataplane.go`'s comment loses "on macOS"). Re-run `make lint` once TP-116 (go1.26.10) is in `rewrite` and merged here: with go1.26.9 vulncheck fails on GO-2026-6809.

Out of scope, filed as a new backlog ticket: an in-place writer (udhcpc, `cat >`) that empties `/etc/resolv.conf` then appends to it is read half-written and loses its lines to the managed rename (pre-existing; with this change a transient empty read also clears the stale report).
Round 2 (2026-10-21): correctness, design and a second-opinion review.
- [ ] R2.1 Blocker: `setResolved` runs `firstRead` before `Update(c)` sets `r.cfg`, so on a stub host whose uplink file appears between the agent's failed read and `SetSystem`, `firstRead` returns a closure over a nil `Upstreams` and the watch goroutine panics (the agent dies); the stored list is also filtered with nil `Servers`. One constructor (e.g. `newResolved(conn, index, c, uplink, uplinkFile)`) that sets `cfg` and `untold` the way `setResolved` needs, used by `setResolved` and by the tests (no hand-built `resolved{…}`), and a nil guard in `firstRead` like `apply`'s. A test for exactly this ordering (untold, uplink readable at setup → told once, no panic).
- [ ] R2.2 A link whose target resolves to the managed path itself (`resolv.conf`, `./resolv.conf`, `foo/../../resolv.conf`): after the takeover the target read returns the node's own file, its servers are filtered out, and the first good read tells nil and clears stale. Skip a target that is the managed file (compare cleaned absolute paths, or `os.SameFile`). Test it.
- [ ] R2.3 `toldNothing` checks the channel once, before the watch goroutine's setup tell can run, so a "tells at every setup" mutant passes most of the time. Wait a short while (e.g. 200 ms) before deciding nothing was told.
- [ ] R2.4 `resolved.read` returns a good, empty read when `!r.uplink`, contradicting its comment. Read only when `uplink` (setup and watch check it), and drop that branch.
- [ ] R2.5 `upstreamsFromContent`'s `ok bool` loses the cause: return an error (`dns: reading resolved's uplink %s: %w`) so the agent's warning tells ENOENT from EACCES.
- [ ] R2.6 While untold, a stub target appearing with the uplink still missing logs "no upstream to ask; set one with -dns-upstream", though the agent already warned the resolvers are unknown. Don't log that while untold.
- [ ] R2.7 The `Upstreams` contract still says "called from the configuration's own goroutine", but `resolvConf.Update` tells on its caller's goroutine (after unlocking). Reword: called without the configuration's lock held, from its own goroutine or from Update's caller.
- [ ] R2.8 Text: the Log's "has-errors → in-progress" line belongs right after the round-1 "review → has-errors" line, not after "in-progress → review" (move it); DESIGN.md:146 drop "too" (nothing earlier in the Linux part says stale); say in DESIGN that a stub host whose resolved never writes its uplink file stays `dns_upstreams_stale`; the "told whatever it found" comment once (in `startsUntold`'s), not three times; the "clears untold" comment above the line that clears it; `system_linux_test.go` "the staleness cleared" on a test that never was stale.
- [ ] R2.9 The lab subtest checks only that `dns_upstreams_stale` clears: also resolve a `direct` name after it, so it proves the upstreams were told.

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
- 2026-10-21 round 1: apply returns the tell and callers run it after unlocking, setup hands the first one to the watch goroutine (R1.1); startsUntold once in the OS-neutral file, resolved's tell names resolvConf's, firstRead → firstGoodRead (R1.9)
- 2026-10-21 an unreadable uplink file is a failed read in SystemUpstreams, resolvConf's untold read and resolved's; where a read already happened, the previous upstreams are kept (R1.2); while untold over a managed file with a recorded link target, the target is read relative to the file's directory (R1.3)
- 2026-10-21 resolved's uplink path is a field and its reads are firstRead and apply, unit-tested (missing → stale, appears → told, unchanged → silent) and covered in the lab's systemd-resolved case (R1.4), correcting the earlier "not verified in unit tests" line; resolved stores the filtered list, so the first tick doesn't tell the same servers again (R1.5)
- 2026-10-21 the default path (Upstreams set, UpstreamsUnknown false) has a setup test and one for a change after a first apply that wrote nothing (R1.6); an original without a trailing newline is not a change (originalEqual) (R1.7)
- 2026-10-21 DESIGN's Linux DNS states the failed-first-read rule (R1.8)
- 2026-10-21 R1.10: resolver.go's warning was already OS-neutral and dataplane.go's comment lost "on macOS" in 112c351; TP-116 (go1.26.10) merged from origin/rewrite, make lint green
- 2026-10-21 mutation checks (unit): upstreamsFromContent answering empty on an unreadable uplink, dropping the link-target read, resolved's read treating a failed read as good, resolved's read returning the raw list, originalEqual → bytes.Equal, and untold: c.Upstreams != nil each fail the new tests; (lab) upstreamsFrom swallowing the failed read fails the systemd-resolved case's new scenario
- 2026-10-21 make lint, make test green per commit; make lab-test green at 8aff73e (lab and node phases both ok, about 3 minutes)
- 2026-10-21 in-progress → review
- 2026-10-21 review → has-errors (round 2: R2.1–R2.9)
- 2026-10-21 has-errors → in-progress (round 2 findings)
