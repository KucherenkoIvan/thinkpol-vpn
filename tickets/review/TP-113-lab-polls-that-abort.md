---
id: TP-113
title: "lab: polls that abort instead of retrying"
milestone: M2
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-099]
refs: []
owner: "agent-claude"
branch: "tp-113-lab-polls-that-abort"
---

## Goal
A lab poll retries a failed read and fails only at its deadline; a one-shot check fails at once. Today some polls call `MustExec` or `t.Fatalf` inside `lab.Eventually`, so one transient `docker exec` error aborts the test instead of being retried.

## Scope
- lab/routetable_test.go: `thinkpol status` via `MustExec` inside the TUN-down poll (~250); `deviceCounters` (`MustExec`, ~424) inside the polls at ~143 and ~204; `routeDev`'s `Fatalf` (~409) inside the poll at ~258.
- Any other `MustExec`/`Fatalf` reached from inside `lab.Eventually` in lab/ (grep for them).
- Reads inside a poll use the short poll bound TP-099 named (`pollTimeout`); one-shot checks the long one (`execTimeout`).

## Out of scope
- Changing what the tests check.

## Acceptance
- [x] no `MustExec` or `Fatalf` is reachable from inside a `lab.Eventually` callback in lab/ (listed in the Log, with the grep used)
- [x] `make lint`, `make test`, `make lab-test` pass

## Notes
- Origin: TP-099's round-6 correctness review (2026-10-19). TP-099 fixed the same pattern in the DNS and disconnect tests; these are outside its scope.
- Also seen flaking (2026-10-19, TP-101's run, passed on rerun and on rewrite): `internal/dataplane/blobs` `TestABlobInTheStoreNeedsNoPeer`. Look at its timing assumptions while here.

## Log
- 2026-10-19 created in backlog (TP-099 review round 6)
- 2026-10-19 notes: a flaky blobs unit test to look at
- 2026-10-19 backlog → in-progress — owner: agent-claude, branch: tp-113-lab-polls-that-abort
- 2026-10-19 grep: `grep -rn 'lab.Eventually(' lab/`, each callback body printed (awk to its closing `})`) and filtered with `grep -E 'MustExec|Fatal|\(t, |t\.Context\(\)'`; helpers called from a callback read one level deep (fetch, reaches, run, cli, wantConnected, resolve, health, xrayLogs: none fails the test). After the change the filter finds only the `Eventually(t, ...)` lines themselves and `xrayLogs(t, l)`, which returns a string.
- 2026-10-19 changed: routetable_test.go routeDev and deviceCounters return errors (polls at :161, :225 and :287 read with pollTimeout; one-shot callers go through routeNow/countersNow, execTimeout, t.Fatal), :275 `thinkpol status` via execRead(pollTimeout); censor_e2e_test.go :235, :283 MustExec → execRead(pollTimeout); unbounded or minute-long reads inside polls bounded by pollTimeout: smoke_test.go :247, agentlock_test.go :55, blobs_test.go :94, :129, :146 (reaches), localapi_test.go :111.
- 2026-10-19 blobs TestABlobInTheStoreNeedsNoPeer: not a sleep or a deadline but a race. obtain published a blob (hold, so Get succeeds) and counted it (Loaded/Fetched) under two separate lock acquisitions; the test waits on Get, then reads Status at once, and a preemption in between shows Loaded=0. hold now applies the counter in its own critical section (service.go:461), so a blob Get returns is already in Status; this also covers the same Get-then-Status reads at service_test.go:269, :319, :342. 300 repeats of the two store tests pass.
- 2026-10-19 transporttest ShapingRefused: not looked at: TP-075 carries no note on it on this branch or on rewrite (TP-055 already replaced its post-Set sleep with connectAdmitted).
- 2026-10-19 verified at 145a246: make lint exit 0, make test exit 0, make lab-test exit 0 (lab ok, node phase 35 packages ok).
- 2026-10-19 in-progress → review
