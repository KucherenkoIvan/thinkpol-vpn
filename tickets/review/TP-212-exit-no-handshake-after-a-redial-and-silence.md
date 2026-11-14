---
id: TP-212
title: "An exit is flagged exit_no_handshake the moment traffic resumes after a re-dial and 15 s of silence"
milestone: M2
area: agent
stream: core
repo: thinkpol-vpn
size: S
depends_on: [TP-210]
refs: [docs/design/api-overview.md#tp-195-health-grades-an-exit-by-its-wireguard-handshake, TP-213]
owner: "agent-tp-212"
branch: "tp-212-exit-graded-from-the-first-initiation-since-the-link"
---

## Goal
An exit whose first hop re-dialed is graded from the first WireGuard initiation sent since the link came back, as api-overview's health row says ("the 15 s start over when it comes back"), so a device whose traffic resumes after a quiet spell doesn't report a false `exit_no_handshake` for a healthy exit.

## Scope
- Trigger: the exit still had an initiation pending from before its first hop dropped; WireGuard stopped retrying for want of traffic; nothing went out for 15 s or more after the link returned; then traffic. Today the first new initiation is graded unanswered the moment it is sent, because the pending one dates from before the re-dial and its age counts from the link's return.
- The flag contradicts docs/design/api-overview.md's health row (line 242) and the comment on ProblemExitNoHandshake (internal/agent/status.go).
- What a member sees: a false `down` blaming the exit, for one round trip, or about 5 s on a lossy link (a phone coming out of a metro tunnel).
- Fix direction: the wg package reports the first initiation sent since the link came up (today it keeps the first unanswered and the last), and exitHandshakes grades from it.
- (from TP-213) Grade as of the status read: dataplane.Status.ReadAt and path.NeighborStatus.UpSince; exitHandshakes takes no clock of its own.

## Out of scope
- The agent tests' 1 s path timings under load (TP-214).
- Grading changes for an exit whose link never dropped, beyond measuring ages to the status read (TP-213's scope).

## Acceptance
- [x] A test reproduces the trigger (a pending initiation, a re-dial, more than the deadline of silence, then traffic) and fails on today's grading; evidence: the failing run on the base commit in the Log.
- [x] With the fix the same test passes and the exit is graded only once an initiation sent after the re-dial has gone unanswered past the deadline; evidence: the passing run and a mutation (grading from the old pending initiation again) that fails it, named in the Log.
- [x] api-overview's health row and the ProblemExitNoHandshake comment match the behaviour; evidence: the diff.
- [x] (from TP-213) Exit health is graded as of the status read: the first hop's coming up and the initiations' ages come from the snapshot's own clock, never from time.Now() at grading; evidence: a deterministic test with the read time injected, and a mutation (grading against time.Now() again) that fails it, named in the Log.
- [x] `make lint`, `make test` and `make lab-test` pass.

## Notes
- Source: TP-210's diagnosis (its Notes, "What a real device shows"). TP-210's test hit the same mechanism with the test's 1 s deadline; at production timings it needs WireGuard to have given up retrying.

## Review findings
- [ ] R1.1 Out of scope's "Grading changes for an exit whose link never dropped" is false since TP-213's fix measures every exit's ages to the status read: say "beyond measuring ages to the status read (TP-213's scope)".
- [ ] R1.2 Scope: add TP-213's part (Status.ReadAt, NeighborStatus.UpSince, exitHandshakes takes no clock of its own) and TP-213 to refs; cite ProblemExitNoHandshake by name, not by line numbers.
- [ ] R1.3 status_test.go: `pendingAcrossARedial` is also used where nothing re-dials; name it after what it builds (firstSinceLinkUp).
- [ ] R1.4 status.go: exitHandshakes' comment said "the default rule's exit", against its own later lines and api-overview; say "an exit carrying a background route (RuleStatus.DefaultExits)", and split the clock caveat from the grading rule.
- [ ] R1.5 wg/doc.go presents FirstInitiationSince as exact: say only the first unanswered initiation and the 15 latest are kept, so for an older moment it answers with the oldest kept, over 70 s old like the true one.
- [ ] R1.6 The new agent test computes linkUp as time.Now() less UpFor, the pattern TP-213 removed: use UpSince.
- [ ] R1.7 No test catches the engine building link-up times from time.Now() less UpFor instead of UpSince: add a deterministic engine test, with a mutation, or say why not.
- [ ] R1.8 (residual risk) The grading clock restarts whenever the first hop's active link changes, not only when the neighbor goes down; and after a first-hop switch, initiations through the old one count against the new one: add both to RR48 with the fix direction.

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
- 2026-11-15 full `make lab-test` on 3984abe (GOFLAGS=-p=2, LAB_P=1, under the full-lab lock), twice: the lab phase green both times; the node phase failed once in internal/dataplane/dns TestResolvConfRestoreAfterARewriteFailedPartwayPutsBackTheWholeOriginal (alone in a lab node: one COUNT=20 run failed, the next passed 20 of 20) and once in internal/agent/supervisor TestIdleStreamsDontStarveRouting (StreamsOverloaded 1), every other package green. Neither package is touched here; the supervisor test fails as often on rewrite at 702f2fe in a lab node under the same load (3 of 10 there, 4 of 10 here, back to back)
- 2026-11-15 merged origin/rewrite at 702f2fe (a97cd1c); on a97cd1c `make lint` and `make test` green (umask 022, 39 packages) and full `make lab-test` green (GOFLAGS=-p=2, LAB_P=1, under the full-lab lock): lab phase and 39 packages
- 2026-11-15 not verified: the trigger end to end at production timings (WireGuard giving up after 90 s, then traffic; the injected 1 s deadline with WireGuard's own retry stands in for it); the engine turning UpFor into an instant with its own clock again has no deterministic test (it needs a stall inside the engine's status read). TP-213's stalled false ok can't happen through the grading now (ages to ReadAt, link-up from UpSince), not re-run under its freezes here
- 2026-11-15 out of scope, for the board: the two node-phase flakes above (dns TestResolvConfRestoreAfterARewriteFailedPartwayPutsBackTheWholeOriginal, supervisor TestIdleStreamsDontStarveRouting under load)
- 2026-11-15 in-progress → review
- 2026-11-15 review round 1: merge, nits R1.1–R1.8
