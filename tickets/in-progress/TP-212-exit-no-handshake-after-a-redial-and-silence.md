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
- [ ] A test reproduces the trigger (a pending initiation, a re-dial, more than the deadline of silence, then traffic) and fails on today's grading; evidence: the failing run on the base commit in the Log.
- [ ] With the fix the same test passes and the exit is graded only once an initiation sent after the re-dial has gone unanswered past the deadline; evidence: the passing run and a mutation (grading from the old pending initiation again) that fails it, named in the Log.
- [ ] api-overview's health row and the ProblemExitNoHandshake comment match the behaviour; evidence: the diff.
- [ ] `make lint`, `make test` and `make lab-test` pass.

## Notes
- Source: TP-210's diagnosis (its Notes, "What a real device shows"). TP-210's test hit the same mechanism with the test's 1 s deadline; at production timings it needs WireGuard to have given up retrying.

## Log
- 2026-11-14 created in backlog (from TP-210)
- 2026-11-15 backlog → in-progress, owner: agent-tp-212
