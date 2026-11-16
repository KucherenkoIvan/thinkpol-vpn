---
id: TP-220
title: "Flaky resolv.conf settle tests under load"
milestone: M2
area: dataplane/dns
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-217]
refs: []
owner: agent-tp-220
branch: tp-220-flaky-resolvconf-settle-tests
---

## Goal
`TestResolvConfASlowWriterPastTheCapKeepsItsServers` and its sibling settle tests (internal/dataplane/dns/resolvconf_settle_test.go) pass reliably under load, for a named root cause, not a retry or a longer timeout.

## Scope
- They pass alone (`make lab-gotest PKG=./internal/dataplane/dns RUN=TestResolvConfA COUNT=10`: 10 of 10) and failed in 3 of 4 full-lab node phases on a Linux Docker 29 host (TP-211's runs, 2026-11-15): `TestResolvConfASlowWriterPastTheCapKeepsItsServers` each time, `TestResolvConfAWriterThatNeverSettlesIsTakenBackAtTheCap` once.
- Reproduce under load (a full lab beside it, or the SIGSTOP freezes and busy loops TP-217 used), name the cause, and fix it in the test or the code.
- First read TP-217's code (merged, or its branch while it is in review): it fixed two other tests in this package, the restore after a failed rewrite and the file renamed in, and changed when the take-over's watch starts. The settle tests may share a cause with them or with that change.

## Out of scope
- The tests TP-217 fixed.

## Acceptance
- [x] The root cause named in Notes, with the failing run's evidence.
- [x] A fix in the test or the code, with the docs it touches updated.
- [x] The settle tests pass 20 runs under load (a full lab or the same freezes beside them) on Linux, and a mutation that brings the cause back fails them.
- [x] No retries and no longer timeouts without a cause.

## Notes
- **Two causes, one per test.** Reproduced on Linux under SIGSTOP/SIGCONT freezes of the test binary (stops of 50 to 700 ms, gaps of 0 to 300 ms, as TP-217 did): on the package as on rewrite, 30 runs each, SlowWriter failed 6 and NeverSettles 5. In a lab container beside another full lab (`make lab-gotest … COUNT=20`, the ticket's setting) SlowWriter failed 6 of 20 and NeverSettles passed 20 of 20.
- **SlowWriter: a race in the product.** A take-back read the file, rendered the managed file, wrote and synced it as a new file, then renamed it over the path. A line an in-place writer appended between the read and the rename went into the file the rename replaced and was lost, though RR5 says such a writer loses nothing while the node runs. The new file's sync is the window: microseconds on a tmpfs, hundreds of milliseconds on a loaded disk (a lab container's files are on the Docker disk), and a stall lines the writer up with it. A temporary trace (8468224c, removed in 60a7fa20) under the freezes, from a run that lost `search lan`:
  ```
  +0s    truncated inode 792756
  +503ms append "search lan\n" into inode 792756; the path now inode 792756
  +503ms take-back: read inode 792756 ""
  +503ms take-back: wrote, the path now inode 792757 (err <nil>)
  ```
  The take-back had read the file empty; the append (logged at its close) landed in that same inode, which the rename then replaced.
- **The fix (product).** `replace` asks the rewrite's check right before the rename (after the sync): the path must still hold what was read (the same file, link and content), or the rewrite writes nothing (`errChangedSinceRead`). The watch then settles that write as still going on, judged at its next wake (the write's own change event, or the poll), so it doesn't spin; Update leaves its configuration to the watch (Deferred says so); the take-over writes and tells nothing, keeps its read as what later changes are told against, and the watch settles the file (a file is the node's own only once the node has written one). A take-back past the settle's cap writes without the check: with it, a writer that writes again within every take-back (faster than the sync) was never taken back. doc.go and RR5 say so.
- **Left, in RR5.** A write the path doesn't show yet when the check reads it: a writer that opened the file before the check and writes after the rename (an open file with no new byte; a rename can't see open files), a write between the check and the rename, and any write during a take-back past the cap. A second trace on the fix (5587c876, removed in a8926c2b), 2 of 150 runs under the freezes losing a line:
  ```
  +1.846475s take-back: read inode 859284 "...#thinkpol-original search lan\nnameserver 192.0.2.7\n"
  +1.846834s writer: opened inode 859284
  +1.846919s writer: appended "nameserver 2001:db8::7\n" into inode 859284; the path now inode 859291
  ```
  The writer opened the file after the take-back's read and before its check, and wrote after its rename. SlowWriter now makes each write under the configuration's lock, so none falls inside a take-back; what the take-back guarantees for a write before its check is TestResolvConfAWriteDuringATakeBackIsNotLost's. Closing the rest would take keeping the replaced file open across the rename and watching it (inotify on that inode) to take in what lands there: not done here.
- **NeverSettles: the test's bound.** It bounded the take-back by wall time from the start: 1.3 s (the cap and a settle). Under the freezes the whole process stops, the watch's timers with it, so the take-back lands at the end of the stall: the failing runs' writer opened the file at e.g. 0, 521, 917, 1527 ms (100 ms due each time), taken back after the 1527 ms open. And in the lab the take-back's own sync took long enough that the rename landed after the bound with the writer not stalled (on cdf7a333, 1 of 20: "taken back after 1.36s running (5.6ms stalled)"). The bound is unchanged; it now applies to when the take-back began writing (a wrapper on `r.rewrite`) less the stalls the writer measured (how late each open came after its sleep).
- **A regression found on the way.** With the check and no exception at the cap (fadf0364), NeverSettles failed 15 of 20 in a lab container beside another full lab, never taken back or taken back at 2 to 3 s: every take-back found the file written during its sync. Fixed by the cap's exception (8e754a9e) and its test.

## Log
- 2026-11-15 created in backlog (from TP-211's and TP-197's lab runs)
- 2026-11-16 backlog → in-progress, owner: agent-tp-220
- 2026-11-16 reproduced on Linux under SIGSTOP freezes of the test binary (stops of 50 to 700 ms, gaps of 0 to 300 ms) on e46c1db6 (the package as on rewrite): SlowWriter failed 6 of 30, NeverSettles 5 of 30; a temporary trace (8468224c) named SlowWriter's cause, the lost line landing in the file the take-back's rename replaced (Notes); in a lab container beside another full lab (lab-gotest COUNT=20) on e46c1db6, SlowWriter failed 6 of 20 and NeverSettles passed 20 of 20
- 2026-11-16 fix, product (60a7fa20, 8e754a9e): a rewrite asks right before its rename whether the path still holds what it read, and writes nothing otherwise; the watch settles that write, Update leaves its configuration to the watch, the take-over writes and tells nothing and keeps its read as the baseline; a take-back past the cap writes without the check. Docs: doc.go and RR5 (a5a1d763, cdf7a333)
- 2026-11-16 fix, tests: SlowWriter makes each write under the configuration's lock (a8926c2b; the residual in Notes, traced on 5587c876); NeverSettles discounts the stalls its writer measured (60a7fa20) and times when the take-back began writing, not the rename (5fdae489); the bound itself is unchanged
- 2026-11-16 new tests: TestResolvConfAWriteDuringATakeBackIsNotLost, TestResolvConfAnUpdateOverAWriteSinceItsReadWaitsForIt, TestResolvConfAWriteDuringTheTakeOverIsNotLost (upstreams known and unknown), TestResolvConfAFileCreatedDuringTheTakeOverOfNoFileSettles, TestResolvConfATakeBackAtTheCapWritesOverAWriteSinceItsRead
- 2026-11-16 mutations, plain go test on macOS, 3 runs each, each failing 3 of 3: M1 the check never asked: the four write-during tests (the line lost; "taken at once"); M2 the take-over failing on a changed file: both take-over tests; M3 Update returning it: the Update test; M4 the watch handling it as a failed take-back: the take-back test ("reported as a failed take-back"); M5 the stale read recorded and told (apply's order before the fix): the take-over test with the upstreams unknown (the stale servers told first); M6 a file taken as the node's own before the node wrote one: the no-file take-over test ("taken at once"); M7 the take-over's read not kept as the baseline: the take-over test with the upstreams known ("told nothing"); M10 no exception at the cap: the cap test ("never taken back; 240 take-backs each found the file written since their read"); M11 every take-back without the check: the take-back test (the line lost); M12b the cap at twice settleMax: NeverSettles ("the take-back began after 2.0s"). M12, decide's cap alone doubled, survived: quietFor still ends the settle at settleMax, so it is no later cap
- 2026-11-16 mutations under the same freezes on macOS: M8a, the product and SlowWriter as on rewrite (no check, writes not under the lock), failed SlowWriter 13 of 30; M9 and M9b, NeverSettles without the stall discount (60a7fa20's and 5fdae489's forms), failed 9 and 12 of 30. Not a settle-test mutation: the check removed with SlowWriter's writes under the lock passes it (the lock excludes the race; M1 fails the deterministic tests). Not run as a mutation: NeverSettles timed at the rename, which needs a loaded lab disk and a mutated branch on the remote; the cdf7a333 lab run in Notes is that case unmutated
- 2026-11-16 on Linux on 5fdae489: under the freezes SlowWriter and NeverSettles passed 100 of 100 each, the five new tests 30 of 30 each; in a lab container beside another full lab (lab-gotest COUNT=20) all seven passed 20 of 20. Earlier heads: a8926c2b 100 of 100 each under the freezes; 60a7fa20 (the check, SlowWriter not yet under the lock) SlowWriter 99 of 100, the one failure the residual in Notes
- 2026-11-16 `make lint` and `make test` green on 5fdae489 (umask 022)
- 2026-11-16 handoff: the full `make lab-test` on 5fdae489 has not run: two waits of 2 h each for the full-lab lock (taken by other labs meanwhile) ran out; the second request stays queued and runs the lab when it gets the lock. Left in in-progress until a full lab is green on the final commit, then in-progress → review
