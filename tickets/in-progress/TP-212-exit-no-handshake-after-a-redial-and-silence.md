---
id: TP-212
title: "An exit is flagged exit_no_handshake the moment traffic resumes after a re-dial and 15 s of silence"
milestone: M2
area: agent
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-210]
refs: [docs/design/api-overview.md#tp-195-health-grades-an-exit-by-its-wireguard-handshake]
owner: "agent-tp-212"
branch: "tp-212-exit-graded-from-the-first-initiation-since-the-link"
---

## Goal
An exit whose first hop re-dialed is graded from the first WireGuard initiation sent since the link came back, as api-overview's health row says ("the 15 s start over when it comes back"), so a device whose traffic resumes after a quiet spell doesn't report a false `exit_no_handshake` for a healthy exit.

## Scope
- Trigger: the exit still had an initiation pending from before its first hop dropped; WireGuard stopped retrying for want of traffic; nothing went out for 15 s or more after the link returned; then traffic. Today the first new initiation is graded unanswered the moment it is sent, because the pending one dates from before the re-dial and its age counts from the link's return.
- The flag contradicts docs/design/api-overview.md's health row (line 242) and the ProblemExitNoHandshake comment (internal/agent/status.go:473-476).
- What a member sees: a false `down` blaming the exit, for one round trip, or about 5 s on a lossy link (a phone coming out of a metro tunnel).
- Fix direction: the wg package reports the first initiation sent since the link came up (today it keeps the first unanswered and the last), and exitHandshakes grades from it.

## Out of scope
- The agent tests' 1 s path timings under load (TP-214).
- Grading changes for an exit whose link never dropped.

## Acceptance
- [x] A test reproduces the trigger (a pending initiation, a re-dial, more than the deadline of silence, then traffic) and fails on today's grading; evidence: the failing run on the base commit in the Log.
- [x] With the fix the same test passes and the exit is graded only once an initiation sent after the re-dial has gone unanswered past the deadline; evidence: the passing run and a mutation (grading from the old pending initiation again) that fails it, named in the Log.
- [x] api-overview's health row and the ProblemExitNoHandshake comment match the behaviour; evidence: the diff.
- [x] (from TP-213) Exit health is graded as of the status read: the first hop's coming up and the initiations' ages come from the snapshot's own clock, never from time.Now() at grading; evidence: a deterministic test with the read time injected, and a mutation (grading against time.Now() again) that fails it, named in the Log.
- [ ] `make lint`, `make test` and `make lab-test` pass.

## Notes
- Source: TP-210's diagnosis (its Notes, "What a real device shows"). TP-210's test hit the same mechanism with the test's 1 s deadline; at production timings it needs WireGuard to have given up retrying.

## Log
- 2026-11-14 created in backlog (from TP-210)
- 2026-11-15 backlog → in-progress, owner: agent-tp-212
- 2026-11-15 reproduced on base code (1e4f606: the test alone on d191d00): TestAnExitPendingAcrossARedialIsGradedFromTheNextInitiation failed 3 of 3, each flagged 7 to 17 ms after the first initiation since the link came back, after 5.0 to 5.3 s of silence. The deadline is injected (1 s) and WireGuard's own 5 s retry stands in for traffic resuming after it gave up (90 s); the grading path is the same
- 2026-11-15 fix (3bff0bd): wg keeps a peer's unanswered initiations (the first and the 15 latest) and Device.FirstInitiationSince picks the first at or after a moment; the engine asks it with the first hop's link-up time (dataplane.PeerStatus.FirstInitiationSinceLinkUp, replacing LastInitiation); exitHandshakes grades from it. Docs: api-overview's health row and api-overview-reference's same sentence, ProblemExitNoHandshake, exitHandshakes, wg/doc.go
- 2026-11-15 on 3bff0bd the test passed 5 of 5, flagged 1.005 to 1.011 s after the first initiation since the link came up (sent 5.0 to 5.3 s after it). Mutations, each caught: M1 wg's firstSince ignoring the moment, so the grading is from the old pending initiation again (the new test: flagged with no initiation since the link came up; wg TestTheFirstInitiationSinceAMomentSkipsOnesBeforeIt and TestAPeerRetriedForLongKeepsItsFirstAndLatestInitiations); M2 exitHandshakes ignoring whether the first hop is up (TestExitsAreGradedByTheirHandshakes, both first-hop-down cases); M3 the trimming dropping the first initiation (TestAPeerRetriedForLongKeepsItsFirstAndLatestInitiations); M4 the engine taking the status read as the link-up time (TestAnExitThatNeverHandshakesIsExitNoHandshake and the new test: never flagged)
- 2026-11-15 on 3bff0bd: `make lint` green; `make test` failed only in TestResolvConfAFileRenamedInIsTakenAtOnce (internal/dataplane/dns, the known flake TP-217 is fixing), 38 packages ok
- 2026-11-15 scope added from TP-213 (orchestrator): exitHandshakes put the first hop's coming up at time.Now() less the snapshot's UpFor, so a stall between reading the status and grading it read an unanswered exit as ok
- 2026-11-15 (from TP-213) fix (8db1536, 3984abe): path.NeighborStatus.UpSince (when the neighbor came up, on the path node's clock) and dataplane.Status.ReadAt (taken before the rest of the read); the engine's link-up times come from UpSince, and exitHandshakes measures ages to st.ReadAt and takes no clock of its own. Tests: TestExitsAreGradedByTheirHandshakes grades statuses read in 2020 (the injected read time), with a case pending 1 ms less than the deadline at the read; path TestANeighborsUpSinceIsWhenItCameUp (fake clock). Mutations, each caught: M5 exitHandshakes grading against time.Now() (on 3984abe: the four cases pending less than the deadline at the read flagged; on 8db1536 the read time was still ahead of the clock, fixed in 3984abe); M6 UpSince as time.Now() less UpFor (the path test)
- 2026-11-15 on 3984abe: `make lint` and `make test` green (umask 022, 39 packages); M1 re-run still fails the new test; the new test 5 of 5
