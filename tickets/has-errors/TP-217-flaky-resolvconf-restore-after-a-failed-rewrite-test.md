---
id: TP-217
title: "Flaky resolv.conf tests under load: the restore after a failed rewrite, and a file renamed in right after the take-over"
milestone: M2
area: dataplane/dns
stream: verification
repo: thinkpol-vpn
size: S
depends_on: [TP-117]
refs: []
owner: "agent-tp-217"
branch: "tp-217-flaky-resolvconf-restore-test"
---

## Goal
`TestResolvConfRestoreAfterARewriteFailedPartwayPutsBackTheWholeOriginal` and `TestResolvConfAFileRenamedInIsTakenAtOnce` (internal/dataplane/dns/resolvconf_settle_test.go, from TP-117) pass reliably under load, each for a named root cause, not a retry.

## Scope
- It failed once in `make test` under load (seen by TP-208's implementer, 2026-11-12). Reproduce it under load (the SIGSTOP freezes TP-210 used, or `-count` beside a full lab), name the cause, and fix it in the test or in the code.
- Added in the work (the second flake, a product fix): the resolv.conf watch is set up before the take-over writes the file, so a file another program renames in right after the take-over is taken at once, not at the 2 s poll; doc.go's watch paragraph says so.

## Out of scope
- Retries, longer timeouts without a cause, skipping under load.

## Acceptance
- [x] The root cause named in Notes, with the evidence (a log or a trace from a failing run).
- [x] The fix; the test passes 20 times under the same load, and a mutation that reverts the fix fails it; evidence: the Log.
- [ ] The watch set up before the take-over writes the file; evidence: TestResolvConfAFileRenamedInIsTakenAtOnce passes 300 of 300 under two busy loops, and failed 116 of 178 with the watch set up in the goroutine again; TestResolvConfIsWatchedBeforeTheTakeOverWrites (the ordering, deterministic) and TestResolvConfTheTakeOverOwnEventIsNotAnotherProgramsWrite (no rewrite loop, no false Problem), each failing under its mutations in the Log.
- [x] `make lint`, `make test` pass.

## Notes
- Source: TP-117 (merged with it); the failure was reported by TP-208's implementer.
- **Root cause (2026-11-14).** A race in the test, not in restore. After its 500 ms sleep the test read resolv.conf without the configuration's lock, while the watch's 100 ms poll retried the failing rewrite (failPartway: `os.WriteFile`, which truncates the file, then writes the cut content) under that lock. The poll's ticks start with the watch, a moment before the test's sleep starts, so the fifth tick lands right at the test's read; a read between the truncation and the write found the file empty, which isn't managed: "the file is not cut inside the original". Load (a stalled thread between the two syscalls, or both timers firing together after a stall) widens that window. The watch itself reads under the lock for this reason (an in-place rewrite's half-written file); the test now does too (readUnderLock; readBetweenRewrites in the Log lines before round 1). The product's restore was right in every failing run.
- **Evidence.** A temporary trace (d139cb5, removed in 0b43931) printed what the failing read found. Under SIGSTOP/SIGCONT freezes of the test binary (gaps 0 to 300 ms, stops 50 to 700 ms), 3 of 100 failed, each the same way:
  ```
  resolvconf_settle_test.go:810: TRACE read at +501.149411ms, 0 bytes "", tries 4 before the read and 5 after
  resolvconf_settle_test.go:810: TRACE read at +535.143095ms, 0 bytes "", tries 4 before the read and 5 after
  resolvconf_settle_test.go:810: TRACE read at +720.577625ms, 0 bytes "", tries 4 before the read and 5 after
  ```
  The fifth try was under way at the read (counted before its write) and the file was empty; a run on macOS (poll only, no change events) failed once in 100 the same way at +500.07 ms.
- **A second flake in the package, fixed here too (product code).** `make test` on the loaded machine then failed `TestResolvConfAFileRenamedInIsTakenAtOnce` ("not taken back", 5 s). setResolvConfTimed started the watch goroutine, which set up the inotify watch itself; under load it started after the test had renamed its file in, so no event came, and the poll (an hour in that test) was the only way left. In the product the poll is 2 s: a file renamed in right after the take-over went unseen, and Problem said nothing, for up to 2 s. The watch is now set up before setResolvConfTimed returns (resolvconf.go, doc.go's watch paragraph says so); since round 1 (R1.1) before the take-over reads and writes the file, so no gap is left between the take-over's write and the watch. The take-over's own write then raises an event, which the watch reads as the node's own file (classify: the content is what it last wrote) and applies again without writing (rewriteResolvConf skips equal content), as the poll already did every 2 s.

## Review findings
Review round 1 (adversarial; Go style): no proven defect in the diff; the test fix is honest (the test raced its own fake). Accepted findings:
- [ ] R1.1 (should-fix) resolvconf.go: the watch is set up after the take-over's own write, so a gap remains (the Lstat, the Unlock and the inotify syscalls). A file renamed in during it (another program reacting to the new TUN) raises no event, Problem reports nil, and the change waits for the 2 s poll. Set the watch up before apply and close it when apply fails; check that the node's own rename (an ownFile event) causes no rewrite loop and no false Problem; a deterministic test of the ordering (a hook on watchFile), mutation-checked.
- [ ] R1.2 (should-fix; in the product before this branch) The bind-mount fallback (writeFile → writeInPlace) opens with O_TRUNC, then writes; a resolver reading in between sees no nameserver. Not fixed here: a RESIDUAL-RISKS.md row, and one follow-up ticket filed (the empty-file window on the in-place fallback).
- [ ] R1.3 (should-fix) Scope and Acceptance name only the restore test; the branch also fixes TestResolvConfAFileRenamedInIsTakenAtOnce with a product change. Add a Scope bullet and an Acceptance box with its evidence, widen the title, and log the widened scope.
- [ ] R1.4 (should-fix) resolvconf_settle_test.go: readBetweenRewrites holds r.mu, so its read can never fall between a rewrite's truncate and its write: rename it readUnderLock.
- [ ] R1.5 (nit) doc.go: rewrap the changed comment; resolvconf.go: reword the watch comment so `changes` doesn't read as the thing closed.

## Log
- 2026-11-14 created in backlog (from TP-117)
- 2026-11-14 backlog → in-progress, owner: agent-tp-217
- 2026-11-14 reproduced without the lab: the unfixed test failed 1 of 100 on macOS with the file read empty mid-rewrite; diagnosis in Notes
- 2026-11-15 fix (0b43931): the test reads the file under the configuration's lock (readBetweenRewrites in resolvconf_settle_test.go); restore and the retry on the poll are unchanged
- 2026-11-15 under SIGSTOP freezes (gaps 0 to 300 ms, stops 50 to 700 ms), 100 runs each: unfixed with the trace (d139cb5) failed 3, each reading 0 bytes during the fifth try; fixed (a39e6b8) passed 100 of 100; mutation M1, readBetweenRewrites without the lock (the fix reverted), failed 4 with "the file is not cut inside the original"
- 2026-11-15 fix (a39e6b8): setResolvConfTimed sets up the inotify watch before it returns (it was set up in the watch goroutine); doc.go updated. Under two busy loops beside the test, TestResolvConfAFileRenamedInIsTakenAtOnce failed 116 of the 178 runs that fit in go test's 10 min on 0b43931 (the mutation: the watch set up in the goroutine again) and passed 300 of 300 on a39e6b8
- 2026-11-15 `make lint` and `make test` green on a39e6b8 (umask 022)
- 2026-11-15 merged origin/rewrite at 16b2f25 (1a2b58e); on 731c903 `make lint` and `make test` green (umask 022), and full `make lab-test` green (GOFLAGS=-p=2, LAB_P=1, under the full-lab lock): lab phase and 39 packages
- 2026-11-15 not verified: the original `make test` failure (no log kept); the reproduction matches its test and assertion only. Out of scope: none found; the resolved watch (system_linux.go) only polls, so it has no such race
- 2026-11-15 in-progress → review
- 2026-11-15 review → has-errors (round 1 findings R1.1–R1.5)
- 2026-11-15 scope widened (R1.3): the title, Goal, Scope and a new Acceptance box now cover the second flake, TestResolvConfAFileRenamedInIsTakenAtOnce, and its product fix (the watch set up before the take-over)
- 2026-11-15 R1.1 (28d4275): setResolvConfTimed sets up the watch before the take-over reads and writes the file, and closes it when the take-over fails; watchResolvConf (a variable over watchFile) lets a test see when the watch begins. The take-over's own write raises an event the watch reads as the node's own file (classify: the content it last wrote) and applies without writing (rewriteResolvConf skips equal content). New tests: TestResolvConfIsWatchedBeforeTheTakeOverWrites (the file still holds the original when the watch begins, and the watch exists when setResolvConfTimed returns; deterministic, every OS) and TestResolvConfTheTakeOverOwnEventIsNotAnotherProgramsWrite (Linux: one change event, the file not written again, no Problem)
- 2026-11-15 R1.1 mutations: M2, the watch set up after the take-over (as on a39e6b8), failed both new tests on a plain `go test` ("watched only after the take-over wrote the file"; "raised no change event"), on Linux and, for the first, on macOS; M1g, the watch set up in the goroutine (before the branch), failed the ordering test on macOS ("not watched yet when the take-over returned"); M3, rewriteResolvConf writing equal content, failed the own-event test (66 change events, the file written again); M4, classify not matching the node's last write, failed it with a false Problem ("another program's file has been at ...")
- 2026-11-15 R1.2: RESIDUAL-RISKS.md RR63 (b9d63f3; doc.go points to it) for the empty file between the in-place fallback's truncation and its write; filed TP-219 (cbc850c) to close or decide it, with the stale-tail trade-off of writing without O_TRUNC then ftruncate
- 2026-11-15 R1.4: readBetweenRewrites renamed readUnderLock (28d4275)
- 2026-11-15 R1.5: doc.go's watch paragraph rewrapped; the watch's comment reworded (28d4275)
