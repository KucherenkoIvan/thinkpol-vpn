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
- [ ] The root cause named in Notes, with the failing run's evidence.
- [ ] A fix in the test or the code.
- [ ] 20 runs under load pass, and a mutation that brings the cause back fails.
- [ ] No retries and no longer timeouts without a cause.

## Notes
- TP-220 left this test out of its scope as a separate flake (its Log, 2026-11-16). The same Log names three more settle tests in the same class under the freezes (TestResolvConfAPollThatReadsAnInPlaceWriteEmptyWaits, TestResolvConfAFileCreatedAtThePathSettles, TestResolvConfAFileCreatedDuringTheTakeOverSettles); worth checking whether one fix covers them.

## Log
- 2026-11-16 created in backlog (from the M2 gate fixes)
- 2026-11-18 backlog → in-progress, owner: agent-tp-235
