---
id: TP-235
title: "Flaky TestResolvConfProblemReportsAWriteThatDoesNotSettle"
milestone: M2
area: dataplane/dns
stream: verification
repo: thinkpol-vpn
size: S
depends_on: []
refs: []
owner: agent-tp-235
branch: tp-235-resolvconf-settle-flake
---

## Goal
`TestResolvConfProblemReportsAWriteThatDoesNotSettle` (internal/dataplane/dns/resolvconf_settle_test.go) fails 15 of 30 under SIGSTOP freezes (seen during TP-220, 2026-11-16). Its writer rewrites the file every 50 ms against a 200 ms settle; during a stall one in-between file stays unchanged for 200 ms, so the node settles it and reports that file's server, as designed. Make the test not depend on timing.

## Scope
- Reproduce under the freezes, confirm the cause, and fix it in the test or the code.

## Out of scope

## Acceptance
- [x] The root cause named in Notes, with the failing run's evidence.
- [x] A fix in the test or the code. (The tests: the product does what doc.go says.)
- [x] 20 runs under load pass, and a mutation that brings the cause back fails. (30 under the freezes and 20 in a lab container, each of the four; M1b in the Log.)
- [x] No retries and no longer timeouts without a cause. (The hour-long settle isn't a wait: the tests end it themselves once the writer is done.)

## Notes
- **The cause: the tests, not the product.** Each of the four tests runs its writer in the test's own process and paused it for a set time (50 to 150 ms) between its writes, against a settle of 200 or 300 ms. A stall of the process (a loaded machine, a SIGSTOP) stops the writer and the watch together; when the process runs again the quiet timer has passed its deadline, the watch reads the file the writer left before the stall, finds it unchanged, and takes it: the file did stay the same for the settle, so the product settles it as doc.go says it should ("the file stays the same, with no change event, for 500 ms"). A real writer is another process, which a stall of the node doesn't stop: if it writes during the node's stall, the watch's read finds the file changed (or takes in the pending change event) and the settle goes on. Under SIGSTOP freezes of the test binary (gaps of 0 to 300 ms, stops of 50 to 700 ms, TP-217's and TP-220's method), 30 runs each on 8f21c8b7 (the package as on rewrite): ProblemReportsAWriteThatDoesNotSettle failed 21, each telling one or two of the writer's in-between files before its last (e.g. `told [[192.0.2.12] [192.0.2.20] [192.0.2.7 2001:db8::7]], want only [192.0.2.7 2001:db8::7]`); APollThatReadsAnInPlaceWriteEmptyWaits failed 4 (3 told the half-written file's `[192.0.2.7]` first, 1 not taken back with the whole file); AFileCreatedAtThePathSettles 5 and AFileCreatedDuringTheTakeOverSettles 4, all "not taken back": the new file settled empty during the stall and was renamed over, and the writer's line went into the replaced file.
- **The fix (tests only).** The four tests step their writer instead of racing it: they start with an hour's settle, so no stall can end one; after each write they wait until the watch has read the file as it now is and is settling it (`seenSettling`, which compares the watch's last read under its lock); once the writer is done, `settleSoon` shortens the settle to 100 ms and wakes the watch, which then takes the writer's whole file. What they assert is unchanged: no in-between file is taken or told, the whole file is, and (ProblemReports) Problem reports unprotected while each write goes on. They now also prove the watch read every in-between state (the empty file, each part), which the timed pauses only hoped for. The product, doc.go and RR5 are unchanged. The four take about 0.3 s each on a host (the three-subtest one 1.1 s), from 2 to 3 s.
- TP-220 left this test out of its scope as a separate flake (its Log, 2026-11-16). The same Log names three more settle tests in the same class under the freezes (TestResolvConfAPollThatReadsAnInPlaceWriteEmptyWaits, TestResolvConfAFileCreatedAtThePathSettles, TestResolvConfAFileCreatedDuringTheTakeOverSettles); worth checking whether one fix covers them.

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
- 2026-11-18 backlog → in-progress, owner: agent-tp-235
- 2026-11-18 reproduced under SIGSTOP freezes of the test binary (gaps 0 to 300 ms, stops 50 to 700 ms), 30 runs each, on 8f21c8b7 (the dns package as on rewrite): ProblemReportsAWriteThatDoesNotSettle failed 21, APollThatReadsAnInPlaceWriteEmptyWaits 4, AFileCreatedAtThePathSettles 5, AFileCreatedDuringTheTakeOverSettles 4; every failure an in-between file of the test's writer settled during a stall (Notes)
- 2026-11-18 fix, tests only (bc528ee3): the four step their writer with an hour's settle, wait for the watch to have read each step (seenSettling), then shorten the settle and wake the watch (settleSoon); the product and its docs unchanged
- 2026-11-18 on Linux on bc528ee3: under the same freezes all four passed 30 of 30; in a lab container (`make lab-gotest PKG=./internal/dataplane/dns RUN=<the four> COUNT=20`, beside other tickets' labs) 20 of 20 each; every TestResolvConf test under the freezes, 10 runs of the set, failed 0; `make lint` and `make test` green (umask 022; lint's first run failed only on govulncheck fetching its database, a network timeout, and passed re-run)
- 2026-11-18 mutations, Linux, in a scratch checkout (not pushed): M1 the four tests' old settles (200/300 ms) back, the stepping kept: survived, 0 of 30 each under the freezes (a stall must land between the watch's read and the writer's next step, a few ms); M1b M1 plus the old writers' 150 ms pause after each step (the cause back): failed under the freezes ProblemReports 17 of 30 ("problem <nil> while the write goes on", in-between files told), AFileCreatedAtThePathSettles 7 of 30, APollThatReadsAnInPlaceWriteEmptyWaits 1 of 30, AFileCreatedDuringTheTakeOverSettles 0 of 30 (one step, before its writer's only write); M2 decide taking a write in place at once (no settle), plain runs: all four fail 3 of 3 ("the watch is not settling the file as it is now"); M3 Problem silent while a write settles: ProblemReports fails 3 of 3 ("problem <nil> while the write goes on")
- 2026-11-18 on macOS (no change events: the watch polls only) on bc528ee3, plain go test, 3 runs: the four pass (the event-only subtests skip); M4, a changed poll read no longer a write still going on (decide's `now != r.foreign.last` dropped): ProblemReports, APollThatReadsAnInPlaceWriteEmptyWaits and AFileCreatedAtThePathSettles/poll fail 3 of 3 ("the watch is not settling the file as it is now"). On Linux the change events keep the settle going on their own, so M4 is caught only where the watch polls, as before this fix
