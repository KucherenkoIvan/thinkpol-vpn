---
id: TP-130
title: "dns: a failed uplink read on the tick resolv.conf changes is never retried"
milestone: M2
area: dataplane
repo: thinkpol-vpn
size: S
depends_on: [TP-128]
refs: []
owner: "agent-tp-130"
branch: "tp-130-resolvconf-failed-uplink-read-on-a-change-never-heals"
---

## Goal
On the resolv.conf path, a read of resolved's uplink file that fails on the tick where resolv.conf changes is retried until it works. The node tells the new upstreams, or reports them stale, instead of keeping the old ones silently.

## Scope
- Today (`resolvconf.go`, `apply`, ~395-410), on a tick where the content changed, `ok=false` still records the new content as the original and tells nothing. Two cases end up there:
  - resolved's uplink file is missing;
  - with TP-128, the uplink file is empty.
- On later ticks `changed` is false, and the first read is no longer owed, so a good uplink read is never told.
- Result: direct names keep going to the previous upstreams until resolv.conf changes again, and `Problem()` returns nil.
- Scenario: upstreams known (`192.0.2.53`). A DHCP client atomically rewrites resolv.conf to `nameserver 127.0.0.53` while the uplink file is missing.
- This predates TP-128. Found by its round-1 correctness review.
- Fix: keep "a read is owed" after a failed read on a change, so the next good read is told, and report `ErrUpstreamsStale` meanwhile. Extend `TestARewrittenResolvConfFiltersStubUpstreams` with the recovery step.

## Acceptance
- [x] a test of the scenario: the failed tick reports stale, and the next tick with a good uplink tells the new upstreams. Mutation: dropping the owed read fails it
- [x] `make lint`, `make test` pass

## Review findings
- [x] R1.1 (should-fix) the read owed after a failed read on a change is told with the first-read rule: an uplink that reads but names no server (resolved's header-only file) tells upstreams(nil), dropping the known direct upstreams with no warning. It must keep the previous upstreams, clear the owed state and log the -dns-upstream hint; nil is told only when the first read is owed (startsUntold)
- [x] R1.2 (nit) doc.go: the resolv.conf section splits an unreadable uplink (previous upstreams kept, stale until a read works) from one that reads but names no server (kept, the log says to set -dns-upstream); the general paragraph says a failed read on a change is stale too

## Log
- 2026-10-22 created in backlog (TP-128 review round 1)
- 2026-11-07 backlog → in-progress, owner: agent-tp-130
- 2026-11-07 finisher: fix ef81a44 (a failed read on a change sets untold while Upstreams is set; doc.go says so); TestARewrittenResolvConfFiltersStubUpstreams now checks stale after the failed tick and the owed read told when the uplink is back; new TestResolvConfAFailedReadOnAChangeWithoutUpstreamsIsNeverStale
- 2026-11-07 finisher: mutation, the `read && changed` case dropped: TestARewrittenResolvConfFiltersStubUpstreams fails (problem <nil>, want stale; never told the owed read); restored, passes
- 2026-11-07 finisher: merged rewrite 7852af8 (head c66ccc8) in as 6b05454; make lint green, make test green
- 2026-11-07 finisher: full make lab-test passed on 6b05454 (LAB_P=4, run alone): lab/ packages ok, gotest ok for 36 packages
- 2026-11-07 in-progress → review
- 2026-11-07 review → has-errors (round 1 findings R1.x)
- 2026-11-07 fix round 1: R1.1 fixed in 61b23c1: the read owed after a failed change is its own state (owed), separate from the first read's (untold); an owed read that names no server keeps the previous upstreams, clears the owed state and logs the -dns-upstream hint; nil is told only for the first read. New TestResolvConfAnOwedReadThatNamesNoServerKeepsTheUpstreams (stale after the failed change; a header-only uplink tells nothing, Problem nil, the hint logged)
- 2026-11-07 fix round 1: mutation, the owed read told with the first-read rule (case firstGoodRead || owedRead): the new test fails (told []); mutation, a good read not clearing owed: it fails (problem stale, no hint logged); both restored, pass
- 2026-11-07 fix round 1: R1.2 doc.go: the resolv.conf section splits an unreadable uplink (kept, stale until a read works) from one that names no server (kept, the log says -dns-upstream); the general paragraph says a failed read of a change is stale too
- 2026-11-07 fix round 1: merged rewrite 4ca1958 in as 0e8a447; make lint green, make test green; full make lab-test passed on 0e8a447 (LAB_P=4, run alone): lab/ packages ok, gotest ok for 36 packages
- 2026-11-07 fix round 1: note: unlike round 1's head, an owed read no longer re-reads a dangling original link's target (linkedOriginal stays first-read only, as before this ticket)
- 2026-11-07 has-errors → review
- 2026-11-07 review → done, merged into rewrite (round 1: go-paranoid, go-style, pocket-torvalds and a same-family second Opus; R1.1–R1.2 fixed; delta check: merge)
