---
id: TP-113
title: "lab: polls that abort instead of retrying"
milestone: M2
area: lab
repo: thinkpol-vpn
size: S
depends_on: [TP-099]
refs: []
owner: ""
branch: ""
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
- [ ] no `MustExec` or `Fatalf` is reachable from inside a `lab.Eventually` callback in lab/ (listed in the Log, with the grep used)
- [ ] `make lint`, `make test`, `make lab-test` pass

## Notes
- Origin: TP-099's round-6 correctness review (2026-10-19). TP-099 fixed the same pattern in the DNS and disconnect tests; these are outside its scope.
- Also seen flaking (2026-10-19, TP-101's run, passed on rerun and on rewrite): `internal/dataplane/blobs` `TestABlobInTheStoreNeedsNoPeer`. Look at its timing assumptions while here.
- Also seen flaking (2026-10-19, TP-075's `make lab-test`, passed alone and on the full rerun): the transport conformance's `ShapingRefused` (`transporttest`) behind the supervisor's shared listeners (`internal/agent/supervisor`, shared_test.go), a timing failure. Look at its timing assumptions while here.

## Log
- 2026-10-19 created in backlog (TP-099 review round 6)
- 2026-10-19 notes: a flaky blobs unit test to look at
- 2026-10-19 notes: a flaky transporttest ShapingRefused run behind the supervisor (TP-075)
